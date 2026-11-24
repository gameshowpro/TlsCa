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
internal sealed partial class TlsCaMdnsService(TlsIdentityManager manager, TlsCaOptions options, TlsCaStatus status, TimeProvider timeProvider, ILogger<TlsCaMdnsService> logger) : BackgroundService
{
    public static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan RetryInterval = TimeSpan.FromSeconds(30);

    // These are how GameshowPro.Mdns words a name conflict in AdvertisedService.Failure (it has no typed flag).
    private static readonly ImmutableArray<string> s_conflictFailures = ["Another mDNS responder owns", "already owned by another"];

    /// <summary>Test seam: creates each advertised service. The default creates a GameshowPro.Mdns <see cref="AdvertisedService"/>.</summary>
    internal Func<InstanceProperties, AdvertisedServiceOptions, ILogger, IMdnsAdvertisement> CreateAdvertisement { get; init; } =
        static (properties, serviceOptions, serviceLogger) => new MdnsAdvertisement(new AdvertisedService(properties, serviceOptions, serviceLogger));

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            bool waitLogged = false;
            while (!stoppingToken.IsCancellationRequested)
            {
                if (manager.CurrentOrDefault is not { } identity)
                {
                    if (!waitLogged)
                    {
                        LogWaitingForIdentity();
                        waitLogged = true;
                    }

                    await Task.Delay(CheckInterval, timeProvider, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                waitLogged = false;
                await Advertise(identity.Name, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            status.NameConflict = false;
        }

        // Advertises the name on the scopes in TlsCaOptions.MdnsScopes, following changes to the
        // list, until the name changes (returns) or the service stops (throws). Every scope is withdrawn before it returns.
        async Task Advertise(string name, CancellationToken stoppingToken)
        {
            Dictionary<ScopeKey, ScopeRun> runs = [];
            bool? wasEmpty = null;
            try
            {
                using PeriodicTimer timer = new(CheckInterval, timeProvider);
                do
                {
                    string? current = manager.CurrentOrDefault?.Name;
                    if (current != name)
                    {
                        if (current is not null)
                        {
                            LogRenamed(name, current);
                        }

                        return;
                    }

                    IReadOnlyList<TlsCaMdnsScope>? scopes = options.MdnsScopes;
                    HashSet<ScopeKey> desired = scopes is null ? [new ScopeKey(null)] : [.. scopes.Select(scope => new ScopeKey(scope))];
                    if (desired.Count == 0 && wasEmpty is not true)
                    {
                        LogNoScopes();
                    }

                    wasEmpty = desired.Count == 0;
                    await Reconcile(name, runs, desired, stoppingToken).ConfigureAwait(false);
                    UpdateConflict(name, runs.Values);
                }
                while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
            }
            finally
            {
                await Withdraw([.. runs.Values]).ConfigureAwait(false);
                runs.Clear();
                status.NameConflict = false;
            }

            // Withdraws the scopes that are no longer wanted (waiting for their goodbyes), then starts the new ones.
            async Task Reconcile(string name, Dictionary<ScopeKey, ScopeRun> runs, HashSet<ScopeKey> desired, CancellationToken stoppingToken)
            {
                ScopeRun[] removed = [.. runs.Values.Where(run => !desired.Contains(run.Key))];
                foreach (ScopeRun run in removed)
                {
                    _ = runs.Remove(run.Key);
                    LogScopeWithdrawn(name, run.Description);
                }

                // A scope withdrawn and added again must not meet its own previous registration, which Mdns would treat as a
                // local conflict.
                await Withdraw(removed).ConfigureAwait(false);

                foreach (ScopeKey key in desired.Where(key => !runs.ContainsKey(key)))
                {
                    ScopeRun run = new(key, CancellationTokenSource.CreateLinkedTokenSource(stoppingToken));
                    runs.Add(key, run);
                    run.Task = RunScope(name, run);
                }

                // One scope's advertisement: started, retried after a failure, and withdrawn when its token is cancelled.
                async Task RunScope(string name, ScopeRun run)
                {
                    // Leave the caller (the reconcile loop) at once: starting includes several hundred milliseconds of probing.
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
#pragma warning disable CA1031 // mDNS trouble must not stop the web server or the other scopes: report it and retry.
                                catch (Exception exception) when (exception is not OperationCanceledException || !token.IsCancellationRequested)
#pragma warning restore CA1031
                                {
                                    bool conflict = IsConflict(exception.Message);
                                    run.StartConflict = conflict;
                                    LogAdvertisingFailed(scope, exception.Message, conflict);
                                    await DisposeAll(services).ConfigureAwait(false);
                                    services = [];
                                    await Task.Delay(RetryInterval, timeProvider, token).ConfigureAwait(false);
                                    continue;
                                }

                                run.StartConflict = false;
                                run.Services = [.. services];
                                LogAdvertising(name, scope);

                                // Runs until withdrawn. A later failure (an interface that goes away and comes back) is Mdns's to
                                // recover; a name conflict is read from Failure by UpdateConflict.
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
                    }

                    IMdnsAdvertisement Create(string name, TlsCaMdnsScope? scope, InstanceProperties properties, string path) =>
                        CreateAdvertisement(
                            properties,
                            new AdvertisedServiceOptions
                            {
                                // One instance name per app keeps two GameshowPro apps on a machine from colliding on _https._tcp.
                                InstanceName = name,
                                HostName = name,
                                NetworkInterfaceId = scope?.NetworkInterfaceId,
                                LocalAddress = scope?.LocalAddress,
                                TxtProperties = new Dictionary<string, string> { ["path"] = path }.ToFrozenDictionary(),
                            },
                            logger);
                }
            }

            // Sets TlsCaStatus.NameConflict from every scope, and logs a scope's conflict when it appears.
            void UpdateConflict(string name, IEnumerable<ScopeRun> runs)
            {
                bool any = false;
                foreach (ScopeRun run in runs)
                {
                    bool running = run.Services.Any(service => IsConflict(service.Failure));
                    if (running && !run.ConflictLogged)
                    {
                        LogNameConflict(name, run.Description);
                    }

                    run.ConflictLogged = running;
                    any |= running || run.StartConflict;
                }

                status.NameConflict = any;
            }
        }
    }

    private static string Describe(TlsCaMdnsScope? scope) =>
        scope is null ? "every eligible interface" : $"interface {scope.NetworkInterfaceId}, address {scope.LocalAddress}";

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

        public ScopeKey Key => key;

        /// <summary>The scope as the log names it.</summary>
        public string Description { get; } = Describe(key.Scope);

        public CancellationTokenSource Stop => stop;

        public Task Task { get; set; } = Task.CompletedTask;

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
