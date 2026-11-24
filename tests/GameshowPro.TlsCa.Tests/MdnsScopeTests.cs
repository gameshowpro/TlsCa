namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// <see cref="TlsCaOptions.MdnsScopes"/>: what <see cref="TlsCaMdnsService"/> passes to GameshowPro.Mdns, how it follows
/// the list while running, retries a scope on its own, and aggregates name conflicts. Most tests replace the advertised
/// service with <see cref="FakeMdns"/> and run the service's clock fast; the last ones use real mDNS on the loopback
/// interface only, so nothing is announced on the test machine's network.
/// </summary>
[TestClass]
public sealed class MdnsScopeTests
{
    private const string ConflictFailure = "Another mDNS responder owns this service or host name.";
    private const string UnavailableFailure = "Selected mDNS interface or address is unavailable.";

    private static readonly TlsCaMdnsScope s_scopeA = new("nic-a", IPAddress.Parse("192.0.2.10"));
    private static readonly TlsCaMdnsScope s_scopeB = new("nic-b", IPAddress.Parse("198.51.100.20"));
    private static readonly TlsCaMdnsScope s_scopeC = new("nic-c", IPAddress.Parse("2001:db8::30"));

    // The scope record and the option

    [TestMethod]
    public void Scope_RejectsAnEmptyInterfaceIdOrANullAddress()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(() => new TlsCaMdnsScope("", IPAddress.Loopback));
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => new TlsCaMdnsScope(null!, IPAddress.Loopback));
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => new TlsCaMdnsScope("nic", null!));
        _ = Assert.ThrowsExactly<ArgumentException>(() => s_scopeA with { NetworkInterfaceId = "" });
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => s_scopeA with { LocalAddress = null! });
        Assert.AreEqual(new TlsCaMdnsScope("nic-a", IPAddress.Parse("192.0.2.10")), s_scopeA);
    }

    [TestMethod]
    public void Option_DefaultsToNull_CopiesTheList_AndRejectsANullElement()
    {
        TlsCaOptions options = new();
        Assert.IsNull(options.MdnsScopes);

        List<TlsCaMdnsScope> list = [s_scopeA];
        options.MdnsScopes = list;
        list.Add(s_scopeB);
        Assert.HasCount(1, options.MdnsScopes);

        _ = Assert.ThrowsExactly<ArgumentException>(() => options.MdnsScopes = [s_scopeA, null!]);
        Assert.HasCount(1, options.MdnsScopes);

        options.MdnsScopes = null;
        Assert.IsNull(options.MdnsScopes);
    }

    // What reaches Mdns

    [TestMethod]
    public async Task NoScopes_AdvertisesOncePerService_Unscoped()
    {
        await using Harness harness = await Harness.Start();

        IReadOnlyList<FakeAdvertisement> started = await harness.WaitForStarted(2);

        Assert.HasCount(2, harness.Mdns.Created);
        foreach (FakeAdvertisement advertisement in started)
        {
            Assert.IsNull(advertisement.Options.NetworkInterfaceId);
            Assert.IsNull(advertisement.Options.LocalAddress);
            Assert.AreEqual(harness.Name, advertisement.Options.InstanceName);
            Assert.AreEqual(harness.Name, advertisement.Options.HostName);
        }

        Assert.AreEqual(9190, started.Single(advertisement => advertisement.Properties.ServiceType == "_https").Properties.Port);
        Assert.AreEqual(9090, started.Single(advertisement => advertisement.Properties.ServiceType == "_http").Properties.Port);
    }

    [TestMethod]
    public async Task AScope_IsPassedThroughToMdns_ForBothServices()
    {
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [s_scopeC]);

        IReadOnlyList<FakeAdvertisement> started = await harness.WaitForStarted(2);

        foreach (FakeAdvertisement advertisement in started)
        {
            Assert.AreEqual("nic-c", advertisement.Options.NetworkInterfaceId);
            Assert.AreEqual(IPAddress.Parse("2001:db8::30"), advertisement.Options.LocalAddress);
            Assert.AreEqual(harness.Name, advertisement.Options.HostName);
        }
    }

    [TestMethod]
    public async Task DuplicateScopes_CountOnce()
    {
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [s_scopeA, new("nic-a", IPAddress.Parse("192.0.2.10"))]);

        _ = await harness.WaitForStarted(2);
        await harness.WaitChecks(3);

        Assert.HasCount(2, harness.Mdns.Created);
    }

    [TestMethod]
    public async Task AnEmptyList_AdvertisesNothing_UntilAScopeIsAdded()
    {
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = []);

        await harness.WaitForLog("list of mDNS scopes is empty");
        await harness.WaitChecks(3);
        Assert.IsEmpty(harness.Mdns.Created);
        Assert.IsFalse(harness.Status.NameConflict);

        harness.Options.MdnsScopes = [s_scopeA];

        IReadOnlyList<FakeAdvertisement> started = await harness.WaitForStarted(2);
        Assert.IsTrue(started.All(advertisement => advertisement.Options.NetworkInterfaceId == "nic-a"));
    }

    // Following the list while running

    [TestMethod]
    public async Task ReplacingTheList_StartsAddedScopes_WithdrawsRemovedOnes_AndLeavesTheRestRunning()
    {
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [s_scopeA, s_scopeB]);
        _ = await harness.WaitForStarted(4);
        FakeAdvertisement[] a = harness.Mdns.For(s_scopeA);
        FakeAdvertisement[] b = harness.Mdns.For(s_scopeB);

        harness.Options.MdnsScopes = [s_scopeC, s_scopeA];

        await harness.WaitUntil(() => harness.Mdns.For(s_scopeC).Count(advertisement => advertisement.Started) == 2, "scope C to start");
        await harness.WaitUntil(() => b.All(advertisement => advertisement.Disposed), "scope B to be withdrawn");
        await harness.WaitChecks(2);

        // Scope A was never touched: the same two services, still running, and no new ones.
        CollectionAssert.AreEqual(a, harness.Mdns.For(s_scopeA));
        Assert.IsTrue(a.All(advertisement => advertisement.Started && !advertisement.Disposed));
        Assert.HasCount(6, harness.Mdns.Created);
        Assert.IsTrue(harness.Logs.Messages.Any(message => message.Contains("from interface nic-b", StringComparison.Ordinal)), harness.AllLogs);

        harness.Options.MdnsScopes = null;

        await harness.WaitUntil(() => harness.Mdns.Created.Count(advertisement => advertisement.Options.NetworkInterfaceId is null && advertisement.Started) == 2, "the unscoped advertisement to start");
        await harness.WaitUntil(() => harness.Mdns.Created.Where(advertisement => advertisement.Options.NetworkInterfaceId is not null).All(advertisement => advertisement.Disposed), "every scoped advertisement to be withdrawn");
    }

    [TestMethod]
    public async Task AScopeThatCannotStart_IsRetried_WhileAnotherKeepsAdvertising()
    {
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [s_scopeA, s_scopeB]);
        harness.Mdns.FailStart(s_scopeB, UnavailableFailure);

        await harness.WaitUntil(() => harness.Mdns.For(s_scopeA).Count(advertisement => advertisement.Started) == 2, "scope A to start");
        await harness.WaitUntil(() => harness.Mdns.StartAttempts(s_scopeB) >= 2, "scope B to be retried");

        // Every failed attempt is disposed; scope A's services are the first two and are still running.
        FakeAdvertisement[] a = harness.Mdns.For(s_scopeA);
        Assert.HasCount(2, a);
        Assert.IsTrue(a.All(advertisement => advertisement.Started && !advertisement.Disposed));
        Assert.IsTrue(harness.Mdns.For(s_scopeB).All(advertisement => !advertisement.Started && advertisement.Disposed));
        Assert.IsFalse(harness.Status.NameConflict);
        Assert.IsTrue(harness.Logs.Messages.Any(message => message.Contains("mDNS advertisement failed on interface nic-b, address 198.51.100.20", StringComparison.Ordinal)), harness.AllLogs);

        harness.Mdns.FailStart(s_scopeB, null);

        await harness.WaitUntil(() => harness.Mdns.For(s_scopeB).Count(advertisement => advertisement.Started && !advertisement.Disposed) == 2, "scope B to start after a retry");
        Assert.IsTrue(a.All(advertisement => !advertisement.Disposed));
    }

    // Name conflicts

    [TestMethod]
    public async Task NameConflict_IsTrueWhileAnyScopeReportsOne_AndClearsWhenNoneDoes()
    {
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [s_scopeA, s_scopeB, s_scopeC]);
        _ = await harness.WaitForStarted(6);
        int changed = 0;
        harness.Status.Changed += (_, _) => Interlocked.Increment(ref changed);

        // A conflict found while running, on one scope.
        harness.Mdns.For(s_scopeA)[0].Failure = ConflictFailure;
        await harness.WaitUntil(() => harness.Status.NameConflict, "the conflict on scope A");
        Assert.AreEqual(1, Volatile.Read(ref changed));
        Assert.IsTrue(harness.Logs.Messages.Any(message => message.Contains("(interface nic-a, address 192.0.2.10) is using the name", StringComparison.Ordinal)), harness.AllLogs);

        // A second scope in conflict; withdrawing the first leaves the conflict in force.
        harness.Mdns.For(s_scopeB)[1].Failure = ConflictFailure;
        harness.Options.MdnsScopes = [s_scopeB, s_scopeC];
        await harness.WaitUntil(() => harness.Mdns.For(s_scopeA).All(advertisement => advertisement.Disposed), "scope A to be withdrawn");
        await harness.WaitChecks(2);
        Assert.IsTrue(harness.Status.NameConflict);

        // A failure that is not a conflict does not count.
        harness.Mdns.For(s_scopeC)[0].Failure = UnavailableFailure;

        // Withdrawing the last conflicting scope clears it.
        harness.Options.MdnsScopes = [s_scopeC];
        await harness.WaitUntil(() => !harness.Status.NameConflict, "the conflict to clear");
        Assert.AreEqual(2, Volatile.Read(ref changed));
        Assert.IsTrue(harness.Mdns.For(s_scopeC).All(advertisement => !advertisement.Disposed));
    }

    [TestMethod]
    public async Task NameConflict_AtStart_IsReported_AndClearsWhenTheScopeIsRemoved()
    {
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [s_scopeA, s_scopeB]);
        harness.Mdns.FailStart(s_scopeB, "The selected mDNS service or host name is already owned by another local registration.");

        await harness.WaitUntil(() => harness.Status.NameConflict, "the start conflict on scope B");
        Assert.IsTrue(harness.Mdns.For(s_scopeA).All(advertisement => !advertisement.Disposed));

        harness.Options.MdnsScopes = [s_scopeA];

        await harness.WaitUntil(() => !harness.Status.NameConflict, "the conflict to clear");
    }

    // Identity

    [TestMethod]
    public async Task ANameChange_RestartsEveryScope()
    {
        string host = TestManagers.HostName;
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [s_scopeA, s_scopeB], () => host);
        _ = await harness.WaitForStarted(4);
        FakeAdvertisement[] first = [.. harness.Mdns.Created];

        host = "Other PC";
        _ = await harness.Manager.ResetIdentity();

        string renamed = DeviceName.Derive("Other PC", TestManagers.AppLabel);
        await harness.WaitUntil(() => harness.Mdns.Created.Count(advertisement => advertisement.Options.HostName == renamed && advertisement.Started) == 4, "every scope to restart under the new name");
        Assert.IsTrue(first.All(advertisement => advertisement.Disposed));
    }

    // Real mDNS, loopback only

    /// <summary>
    /// The scope reaches real GameshowPro.Mdns: the name answers on loopback with the loopback address, and stops answering
    /// once the scope leaves the list.
    /// </summary>
    [TestMethod]
    public async Task RealMdns_AScopedAdvertisementAnswersOnLoopback_AndIsWithdrawn()
    {
        TlsCaMdnsScope loopback = LoopbackScope();
        string name = "tlsca-scope-" + Guid.NewGuid().ToString("N")[..8];
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [loopback], explicitName: name, realMdns: true);

        await harness.WaitForLog($"Advertising {name}.local over mDNS on interface {loopback.NetworkInterfaceId}", TimeSpan.FromSeconds(15));
        Assert.IsTrue(await QueryAddress(name, IPAddress.Loopback, TimeSpan.FromSeconds(5)), harness.AllLogs);
        Assert.IsFalse(harness.Status.NameConflict);

        harness.Options.MdnsScopes = [];

        await harness.WaitForLog("list of mDNS scopes is empty", TimeSpan.FromSeconds(15));
        await Task.Delay(TimeSpan.FromMilliseconds(500));
        Assert.IsFalse(await QueryAddress(name, IPAddress.Loopback, TimeSpan.FromSeconds(2)), harness.AllLogs);
        Assert.IsFalse(harness.AllLogs.Contains("failed", StringComparison.Ordinal), harness.AllLogs);
    }

    /// <summary>
    /// A scope on an interface that does not exist fails to start in real Mdns, and is retried, while a loopback scope
    /// with the same name advertises normally.
    /// </summary>
    [TestMethod]
    public async Task RealMdns_AnAbsentInterface_IsRetried_WhileLoopbackAdvertises()
    {
        TlsCaMdnsScope loopback = LoopbackScope();
        TlsCaMdnsScope absent = new("{00000000-0000-0000-0000-000000000000}", IPAddress.Parse("192.0.2.1"));
        string name = "tlsca-scope-" + Guid.NewGuid().ToString("N")[..8];
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [absent, loopback], explicitName: name, realMdns: true);

        await harness.WaitForLog($"Advertising {name}.local over mDNS on interface {loopback.NetworkInterfaceId}", TimeSpan.FromSeconds(15));
        await harness.WaitUntil(
            () => harness.Logs.Messages.Count(message => message.Contains($"mDNS advertisement failed on interface {absent.NetworkInterfaceId}, address 192.0.2.1", StringComparison.Ordinal)) >= 2,
            "the absent scope to be retried",
            TimeSpan.FromSeconds(15));
        Assert.IsTrue(await QueryAddress(name, IPAddress.Loopback, TimeSpan.FromSeconds(5)), harness.AllLogs);
        Assert.IsFalse(harness.Status.NameConflict);
    }

    /// <summary>
    /// Two scopes with the same name on different interfaces (loopback and a real network) do not conflict with each
    /// other, and each publishes only its own address. Announces a random test name on the machine's network for a few
    /// seconds, so it runs only when <c>TLSCA_TEST_LAN_MDNS=1</c>.
    /// </summary>
    [TestMethod]
    public async Task RealMdns_TheSameNameOnTwoInterfaces_DoesNotConflict()
    {
        if (Environment.GetEnvironmentVariable("TLSCA_TEST_LAN_MDNS") != "1")
        {
            Assert.Inconclusive("Set TLSCA_TEST_LAN_MDNS=1 to announce a test name on the machine's network.");
        }

        TlsCaMdnsScope loopback = LoopbackScope();
        (NetworkInterface nic, IPAddress address) = NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(nic => nic.GetIPProperties().UnicastAddresses
                .Where(entry => entry.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(entry.Address))
                .Select(entry => (Nic: nic, entry.Address)))
            .FirstOrDefault();
        if (nic is null)
        {
            Assert.Inconclusive("No non-loopback IPv4 interface is up.");
        }

        TlsCaMdnsScope network = new(nic.Id, address);
        string name = "tlsca-scope-" + Guid.NewGuid().ToString("N")[..8];
        await using Harness harness = await Harness.Start(options => options.MdnsScopes = [loopback, network], explicitName: name, realMdns: true);

        await harness.WaitForLog($"on interface {loopback.NetworkInterfaceId}", TimeSpan.FromSeconds(15));
        await harness.WaitForLog($"Advertising {name}.local over mDNS on interface {network.NetworkInterfaceId}", TimeSpan.FromSeconds(15));
        await harness.WaitForLog($"Advertising {name}.local over mDNS on interface {loopback.NetworkInterfaceId}", TimeSpan.FromSeconds(15));
        await Task.Delay(TlsCaMdnsService.CheckInterval * 2);

        Assert.IsFalse(harness.Status.NameConflict, harness.AllLogs);
        Assert.IsFalse(harness.AllLogs.Contains("failed", StringComparison.Ordinal), harness.AllLogs);
        IReadOnlyList<IPAddress> answered = await QueryAddresses(name, IPAddress.Loopback, TimeSpan.FromSeconds(5));
        CollectionAssert.AreEqual(new[] { IPAddress.Loopback }, answered.ToArray());
    }

    private static TlsCaMdnsScope LoopbackScope()
    {
        NetworkInterface? nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(candidate =>
            candidate.OperationalStatus == OperationalStatus.Up &&
            candidate.GetIPProperties().UnicastAddresses.Any(entry => entry.Address.Equals(IPAddress.Loopback)));
        if (nic is null)
        {
            Assert.Inconclusive("No loopback interface with 127.0.0.1 is up.");
        }

        return new(nic.Id, IPAddress.Loopback);
    }

    private static async Task<bool> QueryAddress(string name, IPAddress expected, TimeSpan timeout) =>
        (await QueryAddresses(name, expected, timeout)).Contains(expected);

    /// <summary>
    /// Asks for <c>&lt;name&gt;.local</c> A records by multicast on the interface of <paramref name="local"/> (from a port other
    /// than 5353, so the answer comes back by unicast), and returns the addresses in the first answer; empty on timeout.
    /// </summary>
    private static async Task<IReadOnlyList<IPAddress>> QueryAddresses(string name, IPAddress local, TimeSpan timeout)
    {
        byte[] encodedName = [.. $"{name}.local".Split('.').SelectMany(label => (byte[])[(byte)label.Length, .. Encoding.ASCII.GetBytes(label)]), 0];
        ushort id = checked((ushort)Random.Shared.Next(1, ushort.MaxValue));
        byte[] query = [(byte)(id >> 8), (byte)id, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, .. encodedName, 0, 1, 0x80, 1];

        using Socket probe = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, true);
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes());
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 0);
        probe.Bind(new IPEndPoint(local, 0));
        _ = await probe.SendToAsync(query, new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353));

        byte[] buffer = new byte[9000];
        using CancellationTokenSource stop = new(timeout);
        try
        {
            while (true)
            {
                SocketReceiveFromResult received = await probe.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), stop.Token);
                ReadOnlySpan<byte> response = buffer.AsSpan(0, received.ReceivedBytes);
                if (received.RemoteEndPoint is not IPEndPoint { Port: 5353 } || response.Length < 12 ||
                    response[0] != (byte)(id >> 8) || response[1] != (byte)id || (response[2] & 0x80) == 0)
                {
                    continue;
                }

                List<IPAddress> addresses = [];
                // Mdns writes names uncompressed: find each "<name> A IN <ttl> 4 <address>" with a TTL above zero.
                for (int index = response.IndexOf(encodedName); index >= 0;)
                {
                    int record = index + encodedName.Length;
                    if (response.Length >= record + 14 && response[record] == 0 && response[record + 1] == 1 &&
                        response.Slice(record + 4, 4).ContainsAnyExcept((byte)0) && response[record + 8] == 0 && response[record + 9] == 4)
                    {
                        addresses.Add(new IPAddress(response.Slice(record + 10, 4)));
                    }

                    int next = response[(index + 1)..].IndexOf(encodedName);
                    index = next < 0 ? -1 : index + 1 + next;
                }

                if (addresses.Count > 0)
                {
                    return addresses;
                }
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            return [];
        }
    }

    /// <summary>A <see cref="TlsCaMdnsService"/> with a loaded identity, its status, logs, and either fake or real mDNS.</summary>
    private sealed class Harness : IAsyncDisposable
    {
        /// <summary>The service's clock runs this many times faster: checks every 100 ms, retries every 1.5 s.</summary>
        private const int Speed = 20;

        private readonly TempDirectory _directory;
        private readonly ILoggerFactory _loggers;
        private readonly TlsCaMdnsService _service;
        private readonly TimeSpan _checkInterval;

        private Harness(TempDirectory directory, ILoggerFactory loggers, TestLogProvider logs, TlsIdentityManager manager, TlsCaOptions options, TlsCaStatus status, bool realMdns)
        {
            _directory = directory;
            _loggers = loggers;
            Logs = logs;
            Manager = manager;
            Options = options;
            Status = status;
            TimeProvider time = new FastTimeProvider(Speed);
            _checkInterval = TlsCaMdnsService.CheckInterval / Speed;
            _service = realMdns
                ? new(manager, options, status, time, loggers.CreateLogger<TlsCaMdnsService>())
                : new(manager, options, status, time, loggers.CreateLogger<TlsCaMdnsService>()) { CreateAdvertisement = Mdns.Create };
        }

        public FakeMdns Mdns { get; } = new();

        public TestLogProvider Logs { get; }

        public string AllLogs => string.Join(Environment.NewLine, Logs.Messages);

        public TlsIdentityManager Manager { get; }

        public TlsCaOptions Options { get; }

        public TlsCaStatus Status { get; }

        public string Name => Manager.Current.Name;

        public static async Task<Harness> Start(Action<TlsCaOptions>? configure = null, Func<string>? hostName = null, string? explicitName = null, bool realMdns = false)
        {
            TempDirectory directory = new();
            TestLogProvider logs = new();
            ILoggerFactory loggers = LoggerFactory.Create(builder => builder.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
            TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), TimeProvider.System, hostName, o => o.ExplicitName = explicitName);
            _ = await manager.LoadOrCreate();
            TlsCaOptions options = TestManagers.Options(o => (o.HttpPort, o.HttpsPort) = (9090, 9190));
            configure?.Invoke(options);
            TlsCaStatus status = new(manager, options, loggers.CreateLogger<TlsCaStatus>());
            Harness harness = new(directory, loggers, logs, manager, options, status, realMdns);
            await harness._service.StartAsync(CancellationToken.None);
            return harness;
        }

        public async Task<IReadOnlyList<FakeAdvertisement>> WaitForStarted(int count)
        {
            await WaitUntil(() => Mdns.Created.Count(advertisement => advertisement.Started) >= count, $"{count} started advertisements");
            return [.. Mdns.Created.Where(advertisement => advertisement.Started)];
        }

        /// <summary>Lets the service run through at least <paramref name="checks"/> more checks of the list.</summary>
        public Task WaitChecks(int checks) => Task.Delay((_checkInterval * checks) + TimeSpan.FromMilliseconds(100));

        public Task WaitForLog(string fragment, TimeSpan? timeout = null) =>
            WaitUntil(() => Logs.Messages.Any(message => message.Contains(fragment, StringComparison.Ordinal)), $"a log containing \"{fragment}\"", timeout);

        public async Task WaitUntil(Func<bool> condition, string what, TimeSpan? timeout = null)
        {
            DateTime deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
            while (!condition() && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            Assert.IsTrue(condition(), $"Timed out waiting for {what}.{Environment.NewLine}{AllLogs}");
        }

        public async ValueTask DisposeAsync()
        {
            await _service.StopAsync(CancellationToken.None);
            _service.Dispose();
            Status.Dispose();
            Manager.Dispose();
            _loggers.Dispose();
            _directory.Dispose();
        }
    }

    /// <summary>Records every advertisement the service creates, and fails a scope's starts on request.</summary>
    private sealed class FakeMdns
    {
        private readonly Lock _lock = new();
        private readonly List<FakeAdvertisement> _created = [];
        private readonly Dictionary<string, string?> _startFailures = [];
        private readonly Dictionary<string, int> _startAttempts = [];

        public IReadOnlyList<FakeAdvertisement> Created
        {
            get
            {
                lock (_lock)
                {
                    return [.. _created];
                }
            }
        }

        public FakeAdvertisement[] For(TlsCaMdnsScope scope) =>
            [.. Created.Where(advertisement => advertisement.Options.NetworkInterfaceId == scope.NetworkInterfaceId)];

        /// <summary>From now on every start in <paramref name="scope"/> fails with <paramref name="failure"/> (null: succeeds).</summary>
        public void FailStart(TlsCaMdnsScope scope, string? failure)
        {
            lock (_lock)
            {
                _startFailures[scope.NetworkInterfaceId] = failure;
            }
        }

        public int StartAttempts(TlsCaMdnsScope scope)
        {
            lock (_lock)
            {
                return _startAttempts.GetValueOrDefault(scope.NetworkInterfaceId);
            }
        }

        public FakeAdvertisement Create(InstanceProperties properties, AdvertisedServiceOptions options, ILogger _)
        {
            FakeAdvertisement advertisement = new(properties, options, StartFailure);
            lock (_lock)
            {
                _created.Add(advertisement);
            }

            return advertisement;
        }

        private string? StartFailure(FakeAdvertisement advertisement)
        {
            string key = advertisement.Options.NetworkInterfaceId ?? "";
            lock (_lock)
            {
                // One attempt is the pair of services; count it once, at the first service.
                if (advertisement.Properties.ServiceType == "_https")
                {
                    _startAttempts[key] = _startAttempts.GetValueOrDefault(key) + 1;
                }

                return _startFailures.GetValueOrDefault(key);
            }
        }
    }

    private sealed class FakeAdvertisement(InstanceProperties properties, AdvertisedServiceOptions options, Func<FakeAdvertisement, string?> startFailure) : IMdnsAdvertisement
    {
        private volatile bool _started;
        private volatile bool _disposed;

        public InstanceProperties Properties => properties;

        public AdvertisedServiceOptions Options => options;

        public bool Started => _started;

        public bool Disposed => _disposed;

        public string? Failure
        {
            get => Volatile.Read(ref field);
            set => Volatile.Write(ref field, value);
        }

        public Task Start(CancellationToken cancellationToken)
        {
            if (startFailure(this) is { } failure)
            {
                Failure = failure;
                throw new InvalidOperationException(failure);
            }

            _started = true;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>The system clock, with every timer and delay made <c>speed</c> times shorter.</summary>
    private sealed class FastTimeProvider(int speed) : TimeProvider
    {
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            System.CreateTimer(callback, state, Scale(dueTime), Scale(period));

        private TimeSpan Scale(TimeSpan value) => value <= TimeSpan.Zero ? value : value / speed;
    }
}
