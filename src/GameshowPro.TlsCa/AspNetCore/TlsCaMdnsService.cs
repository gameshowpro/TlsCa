namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// Advertises the device name over mDNS together with <c>_https._tcp</c> (path <c>/</c>) and <c>_http._tcp</c> (path
/// <c>/.well-known/gameshowpro/</c>), and reports a name conflict. A failure never stops the web server: it is logged
/// and the advertisement is retried. After an identity reset that changes the name, the advertisement is restarted.
/// While no identity is in force nothing is advertised; the advertisement starts once a reset creates one.
/// <para>
/// <see cref="TlsCaOptions.MdnsScopes"/> decides where: one advertisement per scope (or a single unscoped one), each
/// started and retried on its own, so a scope that cannot start never holds up the others. The list is read every
/// <see cref="CheckInterval"/>; scopes that leave it are withdrawn, new ones are started, and the rest keep running.
/// </para>
/// </summary>
internal sealed partial class TlsCaMdnsService(TlsIdentityManager manager, TlsCaOptions options, TlsCaStatus status, TimeProvider timeProvider, ILogger<TlsCaMdnsService> logger) : BackgroundService, ITlsCaMdns
{
    public static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);

    // These are how GameshowPro.Mdns words a name conflict in AdvertisedService.Failure (it has no typed flag).
    private static readonly ImmutableArray<string> s_conflictFailures = ["Another mDNS responder owns", "already owned by another"];

    private readonly Dictionary<ScopeKey, ScopeRun> _runs = [];
    private readonly object _queueLock = new();
    private Task _queueTail = Task.CompletedTask;
    private string? _name;
    private bool? _wasEmpty;
    private bool _waitLogged;
    private CancellationToken _stoppingToken;
    private volatile bool _running;
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _disposed;

    public Task<TlsCaMdnsApplyResult> ApplyScopesAsync(IReadOnlyList<TlsCaMdnsScope>? scopes, CancellationToken cancellationToken = default) =>
        ApplyScopesCore(scopes, null, cancellationToken);

    public Task<TlsCaMdnsApplyResult> ApplyScopesAsync(IReadOnlyList<TlsCaMdnsScope>? scopes, Func<CancellationToken, Task> afterWithdraw, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(afterWithdraw);
        return ApplyScopesCore(scopes, afterWithdraw, cancellationToken);
    }

    private Task<TlsCaMdnsApplyResult> ApplyScopesCore(IReadOnlyList<TlsCaMdnsScope>? scopes, Func<CancellationToken, Task>? afterWithdraw, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_running)
        {
            throw new InvalidOperationException("The mDNS host service must be running before scopes can be applied asynchronously. Set TlsCaOptions.MdnsScopes before host startup.");
        }

        IReadOnlyList<TlsCaMdnsScope>? snapshot = CopyScopes(scopes);
        return Serialized(async () =>
        {
            using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stoppingToken);
            CancellationToken operationToken = linked.Token;
            operationToken.ThrowIfCancellationRequested();
            if (!_running)
            {
                throw new InvalidOperationException("The mDNS host service has stopped.");
            }

            await RefreshIdentity().ConfigureAwait(false);
            HashSet<ScopeKey> desired = Desired(snapshot);
            ScopeKey[] unchanged = [.. _runs.Keys.Where(desired.Contains)];
            ScopeRun[] removed = [.. _runs.Values.Where(run => !desired.Contains(run.Key))];
            foreach (ScopeRun run in removed)
            {
                _ = _runs.Remove(run.Key);
                LogScopeWithdrawn(_name!, run.Description);
            }

            // Publish the safe intersection before any awaited goodbye. A failure cannot make polling restore an
            // advertisement that the consumer is in the process of replacing.
            options.MdnsScopes = RetainedScopes(unchanged);
            await Withdraw(removed).ConfigureAwait(false);
            try
            {
                operationToken.ThrowIfCancellationRequested();
                if (afterWithdraw is not null)
                {
                    await afterWithdraw(operationToken).ConfigureAwait(false);
                }

                operationToken.ThrowIfCancellationRequested();
            }
            catch
            {
                // A failed consumer transition must not be replayed by the poll loop. Keep only the scopes still live.
                options.MdnsScopes = RetainedScopes(unchanged);
                UpdateConflict();
                throw;
            }

            options.MdnsScopes = snapshot;
            if (_name is null)
            {
                UpdateConflict();
                return new TlsCaMdnsApplyResult(true, false, [], [], []);
            }

            ScopeRun[] started = StartMissing(desired, _stoppingToken);
            await Task.WhenAll(_runs.Values.Where(run => desired.Contains(run.Key)).Select(static run => run.FirstStart.Task)).WaitAsync(operationToken).ConfigureAwait(false);
            UpdateConflict();
            List<TlsCaMdnsStartFailure> failures = [];
            foreach (ScopeRun run in _runs.Values.Where(run => desired.Contains(run.Key)))
            {
                string? message = started.Contains(run) ? run.FirstFailure : run.LastFailure;
                if (message is not null)
                {
                    failures.Add(new TlsCaMdnsStartFailure(run.Key.Scope, message, IsConflict(message)));
                }
            }

            return new TlsCaMdnsApplyResult(
                true,
                true,
                [.. started.Where(static run => run.FirstFailure is null).Select(static run => run.Key.Scope)],
                [.. unchanged.Select(static key => key.Scope)],
                failures);
        }, cancellationToken);
    }

    private static IReadOnlyList<TlsCaMdnsScope>? CopyScopes(IReadOnlyList<TlsCaMdnsScope>? scopes)
    {
        if (scopes is null)
        {
            return null;
        }

        if (scopes.Any(static scope => scope is null))
        {
            throw new ArgumentException("MdnsScopes cannot hold a null element.", nameof(scopes));
        }
        return [.. scopes];
    }

    private static HashSet<ScopeKey> Desired(IReadOnlyList<TlsCaMdnsScope>? scopes) =>
        scopes is null ? [new ScopeKey(null)] : [.. scopes.Select(static scope => new ScopeKey(scope))];

    private static IReadOnlyList<TlsCaMdnsScope>? RetainedScopes(ScopeKey[] unchanged) =>
        unchanged.Any(static key => key.Scope is null) ? null : [.. unchanged.Select(static key => key.Scope!)];

    // Queue links are assigned synchronously at invocation, so competing callers have FIFO order.
    private Task<T> Serialized<T>(Func<Task<T>> action, CancellationToken cancellationToken)
    {
        Task predecessor;
        TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_queueLock)
        {
            predecessor = _queueTail;
            _queueTail = completion.Task;
        }

        return Execute();
        async Task<T> Execute()
        {
            try
            {
                await predecessor.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                return await action().ConfigureAwait(false);
            }
            finally
            {
                _ = completion.TrySetResult();
            }
        }
    }

    private Task<bool> Serialized(Func<Task> action, CancellationToken cancellationToken) =>
        Serialized(async () => { await action().ConfigureAwait(false); return true; }, cancellationToken);

    /// <summary>Test seam: creates each advertised service. The default creates a GameshowPro.Mdns <see cref="AdvertisedService"/>.</summary>
    internal Func<InstanceProperties, AdvertisedServiceOptions, ILogger, IMdnsAdvertisement> CreateAdvertisement { get; init; } =
        static (properties, serviceOptions, serviceLogger) => new MdnsAdvertisement(new AdvertisedService(properties, serviceOptions, serviceLogger));

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
        await _ready.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public override void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            base.Dispose();
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _stoppingToken = stoppingToken;
        _running = true;
        _ = _ready.TrySetResult();
        try
        {
            using PeriodicTimer timer = new(CheckInterval, timeProvider);
            do
            {
                _ = await Serialized(async () =>
                {
                    await RefreshIdentity().ConfigureAwait(false);
                    if (_name is not null)
                    {
                        HashSet<ScopeKey> desired = Desired(options.MdnsScopes);
                        if (desired.Count == 0 && _wasEmpty is not true)
                        {
                            LogNoScopes();
                        }
                        _wasEmpty = desired.Count == 0;
                        await Reconcile(desired, stoppingToken).ConfigureAwait(false);
                    }

                    UpdateConflict();
                }, stoppingToken).ConfigureAwait(false);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            _running = false;
            _ = await Serialized(async () =>
            {
                await Withdraw([.. _runs.Values]).ConfigureAwait(false);
                _runs.Clear();
                status.NameConflict = false;
            }, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task RefreshIdentity()
    {
        string? current = manager.CurrentOrDefault?.Name;
        if (current is null && !_waitLogged)
        {
            LogWaitingForIdentity();
            _waitLogged = true;
        }
        else if (current is not null)
        {
            _waitLogged = false;
        }

        if (current == _name)
        {
            return;
        }
        if (_name is not null)
        {
            if (current is not null)
            {
                LogRenamed(_name, current);
            }
            await Withdraw([.. _runs.Values]).ConfigureAwait(false);
            _runs.Clear();
            status.NameConflict = false;
        }
        _name = current;
    }

    private async Task Reconcile(HashSet<ScopeKey> desired, CancellationToken stoppingToken)
    {
        ScopeRun[] removed = [.. _runs.Values.Where(run => !desired.Contains(run.Key))];
        foreach (ScopeRun run in removed)
        {
            _ = _runs.Remove(run.Key);
            LogScopeWithdrawn(_name!, run.Description);
        }

        await Withdraw(removed).ConfigureAwait(false);
        _ = StartMissing(desired, stoppingToken);
    }

    private ScopeRun[] StartMissing(HashSet<ScopeKey> desired, CancellationToken stoppingToken)
    {
        List<ScopeRun> added = [];
        foreach (ScopeKey key in desired.Where(key => !_runs.ContainsKey(key)))
        {
            ScopeRun run = new(key, CancellationTokenSource.CreateLinkedTokenSource(stoppingToken));
            _runs.Add(key, run);
            run.Task = RunScope(_name!, run);
            added.Add(run);
        }

        return [.. added];
    }

    private async Task RunScope(string name, ScopeRun run)
    {
        await Task.Yield();
        CancellationToken token = run.Stop.Token;
        string scope = run.Description;
        try
        {
            while (true)
            {
                ImmutableList<IMdnsAdvertisement> services = [];
                try
                {
                    try
                    {
                        services = services.Add(Create(name, run.Key.Scope, new InstanceProperties("_https", "tcp", checked((ushort)options.HttpsPort)), "/"));
                        if (options.HttpPort > 0)
                        {
                            services = services.Add(Create(name, run.Key.Scope, new InstanceProperties("_http", "tcp", checked((ushort)options.HttpPort)), TlsCaPaths.WellKnownPrefix + "/"));
                        }

                        foreach (IMdnsAdvertisement service in services)
                        {
                            await service.Start(token).ConfigureAwait(false);
                        }
                    }
#pragma warning disable CA1031 // mDNS trouble must not stop the web server or other scopes.
                    catch (Exception exception) when (exception is not OperationCanceledException || !token.IsCancellationRequested)
#pragma warning restore CA1031
                    {
                        bool conflict = IsConflict(exception.Message);
                        run.StartConflict = conflict;
                        run.LastFailure = exception.Message;
                        if (!run.FirstStart.Task.IsCompleted)
                        {
                            run.FirstFailure = exception.Message;
                        }
                        LogAdvertisingFailed(scope, exception.Message, conflict);
                        await DisposeAll(services).ConfigureAwait(false);
                        services = [];
                        _ = run.FirstStart.TrySetResult();
                        await Task.Delay(RetryInterval, timeProvider, token).ConfigureAwait(false);
                        continue;
                    }

                    run.StartConflict = false;
                    run.LastFailure = null;
                    run.Services = [.. services];
                    _ = run.FirstStart.TrySetResult();
                    LogAdvertising(name, scope);
                    await Task.Delay(Timeout.InfiniteTimeSpan, token).ConfigureAwait(false);
                }
                finally
                {
                    run.Services = [];
                    await DisposeAll(services).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            _ = run.FirstStart.TrySetResult();
        }
    }

    private IMdnsAdvertisement Create(string name, TlsCaMdnsScope? scope, InstanceProperties properties, string path) =>
        CreateAdvertisement(
            properties,
            new AdvertisedServiceOptions
            {
                InstanceName = name,
                HostName = name,
                NetworkInterfaceId = scope?.NetworkInterfaceId,
                LocalAddresses = scope?.LocalAddresses,
                TxtProperties = new Dictionary<string, string> { ["path"] = path }.ToFrozenDictionary(),
            },
            logger);

    private void UpdateConflict()
    {
        bool any = false;
        foreach (ScopeRun run in _runs.Values)
        {
            bool running = run.Services.Any(service => IsConflict(service.Failure));
            if (running && !run.ConflictLogged)
            {
                LogNameConflict(_name!, run.Description);
            }
            run.ConflictLogged = running;
            any |= running || run.StartConflict;
        }

        status.NameConflict = any;
    }

    private static string Describe(TlsCaMdnsScope? scope) =>
        scope is null ? "every eligible interface" : $"interface {scope.NetworkInterfaceId}, address {string.Join(", ", scope.LocalAddresses)}";

    private static bool IsConflict(string? failure) =>
        failure is not null && s_conflictFailures.Any(fragment => failure.Contains(fragment, StringComparison.Ordinal));

    private static async Task Withdraw(IReadOnlyCollection<ScopeRun> runs)
    {
        foreach (ScopeRun run in runs)
        {
            await run.Stop.CancelAsync().ConfigureAwait(false);
        }

        foreach (ScopeRun run in runs)
        {
            await run.Task.ConfigureAwait(false);
            run.Stop.Dispose();
        }
    }

    private static async Task DisposeAll(ImmutableList<IMdnsAdvertisement> services)
    {
        foreach (IMdnsAdvertisement service in services)
        {
            await service.DisposeAsync().ConfigureAwait(false);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Advertising {Name}.local over mDNS on {Scope}.")]
    private partial void LogAdvertising(string name, string scope);

    [LoggerMessage(Level = LogLevel.Warning, Message = "mDNS advertisement failed on {Scope} ({Reason}); name conflict: {Conflict}. Retrying.")]
    private partial void LogAdvertisingFailed(string scope, string reason, bool conflict);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Another device on the network ({Scope}) is using the name {Name}.local. The name is not changed automatically, because the certificates would no longer match; resolve the conflict, or rename this machine and reset the identity.")]
    private partial void LogNameConflict(string name, string scope);

    [LoggerMessage(Level = LogLevel.Information, Message = "Not advertising over mDNS until the TLS identity is reset: there is no identity, so no name to advertise.")]
    private partial void LogWaitingForIdentity();

    [LoggerMessage(Level = LogLevel.Information, Message = "The device name changed from {OldName} to {NewName}; advertising the new name.")]
    private partial void LogRenamed(string oldName, string newName);

    [LoggerMessage(Level = LogLevel.Information, Message = "Not advertising over mDNS: the list of mDNS scopes is empty.")]
    private partial void LogNoScopes();

    [LoggerMessage(Level = LogLevel.Information, Message = "Withdrawing the mDNS advertisement of {Name}.local from {Scope}: the scope left the list.")]
    private partial void LogScopeWithdrawn(string name, string scope);

    /// <summary>A scope, or null for every eligible interface, as a dictionary key.</summary>
    private readonly record struct ScopeKey(TlsCaMdnsScope? Scope);

    /// <summary>One running scope. Its flags are written by its own loop and read by the reconcile loop.</summary>
    private sealed class ScopeRun(ScopeKey key, CancellationTokenSource stop)
    {
        private volatile IMdnsAdvertisement[] _services = [];
        private volatile bool _startConflict;
        private string? _lastFailure;

        public ScopeKey Key => key;

        /// <summary>The scope as the log names it.</summary>
        public string Description { get; } = Describe(key.Scope);

        public CancellationTokenSource Stop => stop;

        public Task Task { get; set; } = Task.CompletedTask;

        public TaskCompletionSource FirstStart { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string? FirstFailure { get; set; }

        public string? LastFailure
        {
            get => Volatile.Read(ref _lastFailure);
            set => Volatile.Write(ref _lastFailure, value);
        }

        /// <summary>The services while they are advertising; empty while starting, waiting to retry or withdrawn.</summary>
        public IMdnsAdvertisement[] Services
        {
            get => _services;
            set => _services = value;
        }

        /// <summary>The last start failed because of a name conflict.</summary>
        public bool StartConflict
        {
            get => _startConflict;
            set => _startConflict = value;
        }

        /// <summary>Read and written by the reconcile loop only.</summary>
        public bool ConflictLogged { get; set; }
    }

    /// <summary>The default <see cref="IMdnsAdvertisement"/>: a GameshowPro.Mdns <see cref="AdvertisedService"/>.</summary>
    private sealed class MdnsAdvertisement(AdvertisedService service) : IMdnsAdvertisement
    {
        public string? Failure => service.Failure;

        public Task Start(CancellationToken cancellationToken) => service.StartAsync(cancellationToken);

        public ValueTask DisposeAsync() => service.DisposeAsync();
    }
}

/// <summary>The part of a GameshowPro.Mdns <see cref="AdvertisedService"/> that <see cref="TlsCaMdnsService"/> uses; a test seam.</summary>
internal interface IMdnsAdvertisement : IAsyncDisposable
{
    /// <summary>Why the advertisement failed (at start or later), else null.</summary>
    string? Failure { get; }

    /// <summary>Starts the advertisement; throws when it cannot start.</summary>
    Task Start(CancellationToken cancellationToken);
}
