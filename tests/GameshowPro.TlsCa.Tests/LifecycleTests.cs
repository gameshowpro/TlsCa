namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Acceptance test 6: create, reload (nothing regenerated), renew (same CA, new leaf key, new serial), reset (new
/// fingerprint, previous recorded), the auto-renew threshold, and a clock earlier than the minimum time.
/// </summary>
[TestClass]
public sealed class LifecycleTests
{
    private static readonly DateTimeOffset s_t0 = new(2026, 11, 22, 10, 30, 15, TimeSpan.Zero);

    [TestMethod]
    public async Task LoadOrCreate_FirstRun_CreatesNameCaAndLeafAndStoresThem()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), new ManualTimeProvider(s_t0));
        List<TlsIdentityChangedEventArgs> changes = [];
        manager.Changed += (_, change) => changes.Add(change);
        Assert.IsFalse(manager.IsLoaded);

        TlsIdentity identity = await manager.LoadOrCreate();

        Assert.IsTrue(manager.IsLoaded);
        Assert.AreSame(identity, manager.Current);
        Assert.AreEqual(TestManagers.Name, identity.Name);
        Assert.AreEqual(TestManagers.Name + ".local", identity.MdnsName);
        Assert.IsNull(identity.PreviousCaFingerprintSha256);
        Assert.IsNull(manager.NameMismatch);

        // The clock (later than the minimum time) is the issuance time.
        Assert.AreEqual(s_t0.AddHours(-48), identity.CaNotBefore);
        Assert.AreEqual(s_t0.AddHours(-48).AddYears(20), identity.CaNotAfter);
        Assert.AreEqual(s_t0.AddHours(-48), identity.LeafNotBefore);
        Assert.AreEqual(s_t0.AddHours(-48).AddDays(800), identity.LeafNotAfter);
        AssertLeafChainsToCa(identity, s_t0);

        X509Certificate2 server = manager.CurrentServerCertificate;
        Assert.IsTrue(server.HasPrivateKey);
        CollectionAssert.AreEqual(identity.LeafCertificateDer.ToArray(), server.RawData);

        using (StoredIdentity? stored = directory.CreateStore().Load())
        {
            Assert.IsNotNull(stored);
            Assert.AreEqual(identity.Name, stored.Name);
            CollectionAssert.AreEqual(identity.CaCertificateDer.ToArray(), stored.CaCertificateDer);
            CollectionAssert.AreEqual(identity.LeafCertificateDer.ToArray(), stored.LeafCertificateDer);
        }

        Assert.HasCount(1, changes);
        Assert.AreEqual(TlsIdentityChange.Created, changes[0].Change);
        Assert.AreSame(identity, changes[0].Identity);
    }

    [TestMethod]
    public async Task LoadOrCreate_LaterRun_LoadsAndRegeneratesNothing()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        TlsIdentity created;
        using (TlsIdentityManager first = TestManagers.Create(directory.CreateStore(), time))
        {
            created = await first.LoadOrCreate();
        }

        byte[] fileBefore = await File.ReadAllBytesAsync(directory.IdentityFile);
        DateTime writtenBefore = File.GetLastWriteTimeUtc(directory.IdentityFile);
        time.Now = s_t0.AddDays(30);

        using TlsIdentityManager second = TestManagers.Create(directory.CreateStore(), time);
        List<TlsIdentityChangedEventArgs> changes = [];
        second.Changed += (_, change) => changes.Add(change);
        TlsIdentity loaded = await second.LoadOrCreate();
        TlsIdentity again = await second.LoadOrCreate();

        Assert.AreEqual(created.Name, loaded.Name);
        CollectionAssert.AreEqual(created.CaCertificateDer.ToArray(), loaded.CaCertificateDer.ToArray());
        CollectionAssert.AreEqual(created.LeafCertificateDer.ToArray(), loaded.LeafCertificateDer.ToArray());
        Assert.AreEqual(created.LeafNotAfter, loaded.LeafNotAfter);
        CollectionAssert.AreEqual(created.LeafCertificateDer.ToArray(), second.CurrentServerCertificate.RawData);
        Assert.AreSame(loaded, again);
        CollectionAssert.AreEqual(fileBefore, await File.ReadAllBytesAsync(directory.IdentityFile), "Loading must not rewrite the file.");
        Assert.AreEqual(writtenBefore, File.GetLastWriteTimeUtc(directory.IdentityFile));
        Assert.HasCount(1, changes, "Only the first LoadOrCreate changes anything.");
        Assert.AreEqual(TlsIdentityChange.Loaded, changes[0].Change);
    }

    [TestMethod]
    public async Task LoadOrCreate_AfterMachineRename_KeepsTheStoredNameAndReportsTheMismatch()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        string host = "Studio PC";
        using (TlsIdentityManager first = TestManagers.Create(directory.CreateStore(), time, () => host))
        {
            _ = await first.LoadOrCreate();
        }

        host = "New Box";
        CollectingLogger logger = new();
        using TlsIdentityManager second = TestManagers.Create(directory.CreateStore(), time, () => host, logger: logger);
        TlsIdentity loaded = await second.LoadOrCreate();

        Assert.AreEqual(TestManagers.Name, loaded.Name, "The stored name stays in force.");
        Assert.AreEqual("new-box-triggergate", second.NameMismatch);
        Assert.IsTrue(logger.Entries.Any(entry => entry.StartsWith("Warning", StringComparison.Ordinal)
            && entry.Contains("new-box-triggergate", StringComparison.Ordinal) && entry.Contains(TestManagers.Name, StringComparison.Ordinal)));

        TlsIdentity renewed = await second.RenewLeaf();
        Assert.AreEqual(TestManagers.Name, renewed.Name, "A renewal never renames.");
        Assert.AreEqual("new-box-triggergate", second.NameMismatch);
    }

    [TestMethod]
    public async Task LoadOrCreate_ExplicitNameChanged_KeepsTheStoredNameAndReportsTheMismatch()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        using (TlsIdentityManager first = TestManagers.Create(directory.CreateStore(), time, configure: o => o.ExplicitName = "uno-a1b2c3"))
        {
            Assert.AreEqual("uno-a1b2c3", (await first.LoadOrCreate()).Name);
        }

        using TlsIdentityManager second = TestManagers.Create(directory.CreateStore(), time, configure: o => o.ExplicitName = "uno-ffffff");
        Assert.AreEqual("uno-a1b2c3", (await second.LoadOrCreate()).Name);
        Assert.AreEqual("uno-ffffff", second.NameMismatch);
    }

    [TestMethod]
    public async Task RenewLeaf_KeepsTheCaAndIssuesANewLeafKeyAndSerial()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time);
        TlsIdentity original = await manager.LoadOrCreate();
        X509Certificate2 originalServer = manager.CurrentServerCertificate;
        List<TlsIdentityChangedEventArgs> changes = [];
        manager.Changed += (_, change) => changes.Add(change);
        time.Now = s_t0.AddDays(100);

        TlsIdentity renewed = await manager.RenewLeaf();

        Assert.AreSame(renewed, manager.Current);
        Assert.AreEqual(original.Name, renewed.Name);
        CollectionAssert.AreEqual(original.CaCertificateDer.ToArray(), renewed.CaCertificateDer.ToArray(), "Same CA.");
        Assert.AreEqual(original.CaFingerprintSha256, renewed.CaFingerprintSha256);
        Assert.IsNull(renewed.PreviousCaFingerprintSha256);
        Assert.AreNotEqual(original.LeafFingerprintSha256, renewed.LeafFingerprintSha256);
        using X509Certificate2 originalLeaf = X509CertificateLoader.LoadCertificate(original.LeafCertificateDer.AsSpan());
        using X509Certificate2 renewedLeaf = X509CertificateLoader.LoadCertificate(renewed.LeafCertificateDer.AsSpan());
        CollectionAssert.AreNotEqual(originalLeaf.PublicKey.EncodedKeyValue.RawData, renewedLeaf.PublicKey.EncodedKeyValue.RawData, "New leaf key.");
        CollectionAssert.AreNotEqual(originalLeaf.SerialNumberBytes.ToArray(), renewedLeaf.SerialNumberBytes.ToArray(), "New serial.");
        Assert.AreEqual(time.Now.AddHours(-48), renewed.LeafNotBefore);
        Assert.AreEqual(time.Now.AddHours(-48).AddDays(800), renewed.LeafNotAfter);
        AssertLeafChainsToCa(renewed, time.Now);

        Assert.AreNotSame(originalServer, manager.CurrentServerCertificate);
        CollectionAssert.AreEqual(renewed.LeafCertificateDer.ToArray(), manager.CurrentServerCertificate.RawData);
        Assert.HasCount(1, changes);
        Assert.AreEqual(TlsIdentityChange.Renewed, changes[0].Change);

        using TlsIdentityManager reloaded = TestManagers.Create(directory.CreateStore(), time);
        CollectionAssert.AreEqual(renewed.LeafCertificateDer.ToArray(), (await reloaded.LoadOrCreate()).LeafCertificateDer.ToArray(), "The renewal was stored.");
    }

    [TestMethod]
    public async Task ResetIdentity_ReplacesCaAndLeafRecordsThePreviousFingerprintAndAdoptsTheCurrentName()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        string host = "Studio PC";
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time, () => host);
        TlsIdentity original = await manager.LoadOrCreate();
        List<TlsIdentityChangedEventArgs> changes = [];
        manager.Changed += (_, change) => changes.Add(change);
        host = "New Box";
        Assert.AreEqual("new-box-triggergate", manager.NameMismatch);

        TlsIdentity reset = await manager.ResetIdentity();

        Assert.AreSame(reset, manager.Current);
        Assert.AreEqual("new-box-triggergate", reset.Name);
        Assert.IsNull(manager.NameMismatch);
        Assert.AreNotEqual(original.CaFingerprintSha256, reset.CaFingerprintSha256);
        Assert.AreEqual(original.CaFingerprintSha256, reset.PreviousCaFingerprintSha256);
        AssertLeafChainsToCa(reset, s_t0);
        using (X509Certificate2 originalCa = X509CertificateLoader.LoadCertificate(original.CaCertificateDer.AsSpan()))
        using (X509Certificate2 resetCa = X509CertificateLoader.LoadCertificate(reset.CaCertificateDer.AsSpan()))
        using (X509Certificate2 resetLeaf = X509CertificateLoader.LoadCertificate(reset.LeafCertificateDer.AsSpan()))
        {
            CollectionAssert.AreNotEqual(originalCa.PublicKey.EncodedKeyValue.RawData, resetCa.PublicKey.EncodedKeyValue.RawData, "New CA key.");
            Assert.IsFalse(TestPki.Validate(originalCa, resetLeaf, s_t0).Valid, "Clients that trust only the old CA reject the new leaf.");
        }

        Assert.HasCount(1, changes);
        Assert.AreEqual(TlsIdentityChange.Reset, changes[0].Change);

        // The previous fingerprint survives a renewal and a reload.
        TlsIdentity renewed = await manager.RenewLeaf();
        Assert.AreEqual(original.CaFingerprintSha256, renewed.PreviousCaFingerprintSha256);
        using TlsIdentityManager reloaded = TestManagers.Create(directory.CreateStore(), time, () => host);
        TlsIdentity loaded = await reloaded.LoadOrCreate();
        Assert.AreEqual(reset.CaFingerprintSha256, loaded.CaFingerprintSha256);
        Assert.AreEqual(original.CaFingerprintSha256, loaded.PreviousCaFingerprintSha256);
    }

    [TestMethod]
    public async Task ResetIdentity_BeforeAnythingIsLoaded_RecordsTheStoredCaFingerprint()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        TlsIdentity stored;
        using (TlsIdentityManager first = TestManagers.Create(directory.CreateStore(), time))
        {
            stored = await first.LoadOrCreate();
        }

        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time);
        TlsIdentity reset = await manager.ResetIdentity();

        Assert.AreEqual(stored.CaFingerprintSha256, reset.PreviousCaFingerprintSha256);
        Assert.AreNotEqual(stored.CaFingerprintSha256, reset.CaFingerprintSha256);
    }

    [TestMethod]
    [DataRow(91, false)]
    [DataRow(90, false)]
    [DataRow(89, true)]
    [DataRow(1, true)]
    [DataRow(-5, true, DisplayName = "Already expired")]
    public async Task RenewIfDue_RenewsOnlyWhenLessThan90DaysRemain(int daysRemaining, bool expectRenewed)
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time);
        TlsIdentity original = await manager.LoadOrCreate();
        time.Now = original.LeafNotAfter.AddDays(-daysRemaining);

        bool renewed = await manager.RenewIfDue();

        Assert.AreEqual(expectRenewed, renewed);
        TlsIdentity current = manager.Current;
        CollectionAssert.AreEqual(original.CaCertificateDer.ToArray(), current.CaCertificateDer.ToArray());
        if (expectRenewed)
        {
            Assert.AreEqual(time.Now.AddHours(-48).AddDays(800), current.LeafNotAfter);
        }
        else
        {
            Assert.AreSame(original, current);
        }
    }

    [TestMethod]
    public async Task RenewIfDue_HonorsAConfiguredThreshold()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time, configure: o => o.RenewWhenRemaining = TimeSpan.FromDays(200));
        TlsIdentity original = await manager.LoadOrCreate();

        time.Now = original.LeafNotAfter.AddDays(-201);
        Assert.IsFalse(await manager.RenewIfDue());
        time.Now = original.LeafNotAfter.AddDays(-199);
        Assert.IsTrue(await manager.RenewIfDue());
    }

    [TestMethod]
    public async Task RenewIfDue_InTheCasFinalDays_ClampsToTheCaThenStopsAndWarns()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        CollectingLogger logger = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time, logger: logger);
        TlsIdentity original = await manager.LoadOrCreate();

        time.Now = original.CaNotAfter.AddDays(-100);
        Assert.IsTrue(await manager.RenewIfDue());
        Assert.AreEqual(original.CaNotAfter, manager.Current.LeafNotAfter, "The leaf is clamped to the CA's notAfter.");
        AssertLeafChainsToCa(manager.Current, time.Now);

        time.Now = original.CaNotAfter.AddDays(-50);
        Assert.IsFalse(await manager.RenewIfDue(), "A renewal cannot extend a leaf that already ends with its CA.");
        Assert.IsTrue(logger.Entries.Any(entry => entry.StartsWith("Warning", StringComparison.Ordinal) && entry.Contains("Reset the identity", StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task Issuing_WithAClockEarlierThanTheMinimumTime_UsesTheMinimumTime()
    {
        using TempDirectory directory = new();
        DateTimeOffset minimum = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        ManualTimeProvider time = new(new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero));
        CollectingLogger logger = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time, configure: o => o.MinimumTime = minimum, logger: logger);

        TlsIdentity created = await manager.LoadOrCreate();
        Assert.AreEqual(minimum.AddHours(-48), created.CaNotBefore);
        Assert.AreEqual(minimum.AddHours(-48), created.LeafNotBefore);

        time.Now = new DateTimeOffset(2010, 1, 1, 0, 0, 0, TimeSpan.Zero);
        TlsIdentity renewed = await manager.RenewLeaf();
        Assert.AreEqual(minimum.AddHours(-48), renewed.LeafNotBefore);

        TlsIdentity reset = await manager.ResetIdentity();
        Assert.AreEqual(minimum.AddHours(-48), reset.CaNotBefore);
        Assert.IsTrue(logger.Entries.Any(entry => entry.StartsWith("Warning", StringComparison.Ordinal) && entry.Contains("earlier than the minimum time", StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task MinimumTime_DefaultsToTheLibraryBuildTime()
    {
        string stamped = typeof(TlsCaOptions).Assembly.GetCustomAttributes(typeof(AssemblyMetadataAttribute), inherit: false)
            .Cast<AssemblyMetadataAttribute>().Single(attribute => attribute.Key == "GameshowPro.TlsCa.BuildTimestamp").Value!;
        DateTimeOffset buildTime = DateTimeOffset.Parse(stamped, CultureInfo.InvariantCulture);
        Assert.AreEqual(buildTime, TlsCaOptions.DefaultMinimumTime);
        Assert.AreEqual(buildTime, new TlsCaOptions().MinimumTime);
        Assert.IsGreaterThan(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), buildTime);
        Assert.IsLessThanOrEqualTo(DateTimeOffset.UtcNow.AddMinutes(1), buildTime);

        // A manager left at the default floors an early clock at the build time.
        using TempDirectory directory = new();
        TlsCaOptions options = new() { AppLabel = TestManagers.AppLabel };
        using TlsIdentityManager manager = new(options, directory.CreateStore(), new ManualTimeProvider(new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero)));
        Assert.AreEqual(buildTime.AddHours(-48), (await manager.LoadOrCreate()).CaNotBefore);
    }

    [TestMethod]
    public async Task Operations_BeforeLoadOrCreate_Throw()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), new ManualTimeProvider(s_t0));

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => manager.Current);
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => manager.CurrentServerCertificate);
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => manager.NameMismatch);
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () => await manager.RenewLeaf());
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () => await manager.RenewIfDue());
        Assert.IsFalse(File.Exists(directory.IdentityFile));
    }

    [TestMethod]
    public async Task Operations_AfterDispose_Throw()
    {
        using TempDirectory directory = new();
        TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), new ManualTimeProvider(s_t0));
        _ = await manager.LoadOrCreate();
        manager.Dispose();
        manager.Dispose();

        _ = Assert.ThrowsExactly<ObjectDisposedException>(() => manager.Current);
        _ = await Assert.ThrowsExactlyAsync<ObjectDisposedException>(async () => await manager.RenewLeaf());
        _ = await Assert.ThrowsExactlyAsync<ObjectDisposedException>(async () => await manager.LoadOrCreate());
    }

    [TestMethod]
    public void Constructor_InvalidOptions_Throw()
    {
        using TempDirectory directory = new();
        FileIdentityStore store = directory.CreateStore();
        ManualTimeProvider time = new(s_t0);

        _ = Assert.ThrowsExactly<ArgumentException>(() => new TlsIdentityManager(new TlsCaOptions(), store, time));
        _ = Assert.ThrowsExactly<ArgumentException>(() => new TlsIdentityManager(new TlsCaOptions { ExplicitName = "Not Valid" }, store, time));
        _ = Assert.ThrowsExactly<ArgumentException>(() => new TlsIdentityManager(new TlsCaOptions { AppLabel = "---" }, store, time));
        _ = Assert.ThrowsExactly<ArgumentException>(() => new TlsIdentityManager(new TlsCaOptions { AppLabel = "app", RenewWhenRemaining = TimeSpan.Zero }, store, time));
        _ = Assert.ThrowsExactly<ArgumentException>(() => new TlsIdentityManager(new TlsCaOptions { AppLabel = "app", RenewWhenRemaining = TimeSpan.FromDays(800) }, store, time));
    }

    [TestMethod]
    public async Task LoadOrCreate_CorruptFile_ThrowsAndNeverCreatesANewIdentity()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        using (TlsIdentityManager first = TestManagers.Create(directory.CreateStore(), time))
        {
            _ = await first.LoadOrCreate();
        }

        byte[] corrupt = [.. (await File.ReadAllBytesAsync(directory.IdentityFile)).Take(200)];
        await File.WriteAllBytesAsync(directory.IdentityFile, corrupt);
        CollectingLogger logger = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time, logger: logger);

        IdentityStoreException exception = await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => await manager.LoadOrCreate());

        StringAssert.Contains(exception.Message, directory.IdentityFile);
        Assert.IsFalse(manager.IsLoaded);
        CollectionAssert.AreEqual(corrupt, await File.ReadAllBytesAsync(directory.IdentityFile), "The unusable file is left as it was.");
        Assert.IsTrue(logger.Entries.Any(entry => entry.StartsWith("Error", StringComparison.Ordinal)));

        // The explicit recovery: a reset replaces the unusable identity.
        TlsIdentity reset = await manager.ResetIdentity();
        Assert.IsTrue(manager.IsLoaded);
        Assert.IsNull(reset.PreviousCaFingerprintSha256);
        using TlsIdentityManager reloaded = TestManagers.Create(directory.CreateStore(), time);
        Assert.AreEqual(reset.CaFingerprintSha256, (await reloaded.LoadOrCreate()).CaFingerprintSha256);
    }

    [TestMethod]
    public async Task LoadOrCreate_InconsistentIdentity_Throws()
    {
        using DeviceIdentity device = TestPki.CreateIdentity(TestManagers.Name, s_t0);
        using DeviceIdentity other = TestPki.CreateIdentity(TestManagers.Name, s_t0);
        StoredIdentity Stored(ECDsa caKey, X509Certificate2 leaf, ECDsa leafKey, string name = TestManagers.Name) => new()
        {
            Name = name,
            CaCertificateDer = device.Ca.RawData,
            CaPrivateKeyPkcs8 = caKey.ExportPkcs8PrivateKey(),
            LeafCertificateDer = leaf.RawData,
            LeafPrivateKeyPkcs8 = leafKey.ExportPkcs8PrivateKey(),
        };

        await AssertInconsistent(() => Stored(other.CaKey, device.Leaf, device.LeafKey), "CA private key");
        await AssertInconsistent(() => Stored(device.CaKey, device.Leaf, other.LeafKey), "leaf private key");
        await AssertInconsistent(() => Stored(device.CaKey, other.Leaf, other.LeafKey), "leaf certificate");
        await AssertInconsistent(() => Stored(device.CaKey, device.Leaf, device.LeafKey, "other-name"), "CA certificate");

        // Control: the consistent identity loads.
        using TlsIdentityManager manager = TestManagers.Create(new FixedStore(() => Stored(device.CaKey, device.Leaf, device.LeafKey)), new ManualTimeProvider(s_t0));
        Assert.AreEqual(TestManagers.Name, (await manager.LoadOrCreate()).Name);

        static async Task AssertInconsistent(Func<StoredIdentity> load, string expected)
        {
            using TlsIdentityManager manager = TestManagers.Create(new FixedStore(load), new ManualTimeProvider(s_t0));
            IdentityStoreException exception = await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => await manager.LoadOrCreate());
            StringAssert.Contains(exception.Message, expected);
            Assert.IsFalse(manager.IsLoaded);
        }
    }

    [TestMethod]
    public async Task RenewAndReset_WhenTheStoreFails_KeepThePreviousIdentityInForce()
    {
        using TempDirectory directory = new();
        FailingStore store = new(directory.CreateStore());
        using TlsIdentityManager manager = TestManagers.Create(store, new ManualTimeProvider(s_t0));
        TlsIdentity original = await manager.LoadOrCreate();
        X509Certificate2 server = manager.CurrentServerCertificate;
        store.FailSaves = true;

        _ = await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => await manager.RenewLeaf());
        _ = await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => await manager.ResetIdentity());

        Assert.AreSame(original, manager.Current);
        Assert.AreSame(server, manager.CurrentServerCertificate);
        Assert.IsTrue(server.HasPrivateKey);
        store.FailSaves = false;
        Assert.AreEqual(original.CaFingerprintSha256, (await manager.RenewLeaf()).CaFingerprintSha256);
    }

    [TestMethod]
    public async Task ConcurrentRenewResetAndReads_NeverObserveAHalfUpdatedIdentity()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time);
        _ = await manager.LoadOrCreate();
        using CancellationTokenSource writersDone = new();

        Task writers = Task.WhenAll(Task.Run(RenewRepeatedly), Task.Run(ResetRepeatedly));
        Task<int>[] readers = [.. Enumerable.Range(0, 4).Select(_ => Task.Run(() => Read(writersDone.Token)))];

        await writers;
        await writersDone.CancelAsync();
        int[] reads = await Task.WhenAll(readers);
        Assert.IsTrue(reads.All(count => count > 0));

        async Task RenewRepeatedly()
        {
            for (int i = 0; i < 15; i++)
            {
                _ = await manager.RenewLeaf();
            }
        }

        async Task ResetRepeatedly()
        {
            for (int i = 0; i < 5; i++)
            {
                _ = await manager.ResetIdentity();
            }
        }

        int Read(CancellationToken stop)
        {
            int count = 0;
            do
            {
                TlsIdentity identity = manager.Current;
                AssertLeafChainsToCa(identity, s_t0);
                X509Certificate2 server = manager.CurrentServerCertificate;
                using ECDsa key = server.GetECDsaPrivateKey()!;
                byte[] data = [1, 2, 3];
                byte[] signature = key.SignData(data, HashAlgorithmName.SHA256);
                using ECDsa publicKey = server.GetECDsaPublicKey()!;
                Assert.IsTrue(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256));
                count++;
            }
            while (!stop.IsCancellationRequested);
            return count;
        }
    }

    [TestMethod]
    public async Task LogsAndErrors_NeverContainKeyMaterial()
    {
        using TempDirectory directory = new();
        ManualTimeProvider time = new(s_t0);
        CollectingLogger logger = new();
        string host = "Studio PC";
        List<StoredIdentity> seen = [];
        List<string> texts = [];
        try
        {
            using (TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), time, () => host, logger: logger))
            {
                _ = await manager.LoadOrCreate();
                Capture();
                _ = await manager.RenewLeaf();
                Capture();
                host = "New Box";
                _ = await manager.ResetIdentity();
                Capture();
                time.Now = manager.Current.CaNotAfter.AddDays(-10);
                _ = await manager.RenewIfDue();
                Capture();
                _ = await manager.RenewIfDue();
                time.Now = new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero);
                _ = await manager.RenewLeaf();
                Capture();
            }

            host = "Studio PC";
            using (TlsIdentityManager mismatched = TestManagers.Create(directory.CreateStore(), time, () => host, logger: logger))
            {
                _ = await mismatched.LoadOrCreate();
            }

            byte[] file = await File.ReadAllBytesAsync(directory.IdentityFile);
            await File.WriteAllBytesAsync(directory.IdentityFile, file[..^40]);
            using TlsIdentityManager failing = TestManagers.Create(directory.CreateStore(), time, logger: logger);
            texts.Add((await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => await failing.LoadOrCreate())).ToString());

            string all = logger.AllText + string.Join(Environment.NewLine, texts);
            Assert.IsGreaterThan(5, logger.Entries.Count);
            foreach (StoredIdentity identity in seen)
            {
                KeyMaterial.AssertAbsent(identity, all);
            }
        }
        finally
        {
            foreach (StoredIdentity identity in seen)
            {
                identity.Dispose();
            }
        }

        void Capture() => seen.Add(directory.CreateStore().Load()!);
    }

    [TestMethod]
    public async Task LocalLeafIssuer_IssuesOnlyForItsCasNameWithAFreshKeyEachTime()
    {
        using DeviceIdentity device = TestPki.CreateIdentity(TestManagers.Name, s_t0);
        LocalLeafIssuer issuer = new(device.Ca, device.CaKey);
        Assert.AreEqual(TestManagers.Name, issuer.Name);

        using IssuedLeaf first = await issuer.Issue(s_t0, CancellationToken.None);
        using IssuedLeaf second = await issuer.Issue(s_t0, CancellationToken.None);

        Assert.AreEqual($"CN={TestManagers.Name}.local", first.Certificate.Subject);
        Assert.IsTrue(TestPki.Validate(device.Ca, first.Certificate, s_t0).Valid);
        CollectionAssert.AreEqual(first.Key.ExportSubjectPublicKeyInfo(), first.Certificate.PublicKey.ExportSubjectPublicKeyInfo());
        CollectionAssert.AreNotEqual(first.Key.ExportSubjectPublicKeyInfo(), second.Key.ExportSubjectPublicKeyInfo());

        _ = Assert.ThrowsExactly<ArgumentException>(() => new LocalLeafIssuer(device.Leaf, device.CaKey), "A leaf is not a device CA.");
        _ = await Assert.ThrowsAsync<OperationCanceledException>(async () => await issuer.Issue(s_t0, new CancellationToken(canceled: true)));
    }

    /// <summary>The leaf in <paramref name="identity"/> validates against its CA (custom root trust) at <paramref name="at"/>.</summary>
    internal static void AssertLeafChainsToCa(TlsIdentity identity, DateTimeOffset at)
    {
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(identity.CaCertificateDer.AsSpan());
        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(identity.LeafCertificateDer.AsSpan());
        (bool valid, X509ChainStatusFlags flags, int length) = TestPki.Validate(ca, leaf, at);
        Assert.AreEqual(X509ChainStatusFlags.NoError, flags);
        Assert.IsTrue(valid);
        Assert.AreEqual(2, length);
        Assert.IsTrue(leaf.MatchesHostname(identity.MdnsName, allowWildcards: false, allowCommonName: false));
        Assert.AreEqual(Fingerprint.Sha256(ca), identity.CaFingerprintSha256);
        Assert.AreEqual(Fingerprint.Sha256(leaf), identity.LeafFingerprintSha256);
    }

    private sealed class FixedStore(Func<StoredIdentity?> load) : IIdentityStore
    {
        public StoredIdentity? Load() => load();

        public void Save(StoredIdentity identity) => throw new AssertFailedException("Not expected to save.");
    }

    private sealed class FailingStore(IIdentityStore inner) : IIdentityStore
    {
        public bool FailSaves { get; set; }

        public StoredIdentity? Load() => inner.Load();

        public void Save(StoredIdentity identity)
        {
            if (FailSaves)
            {
                throw new IdentityStoreException("Simulated write failure.");
            }

            inner.Save(identity);
        }
    }
}
