namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Platform failures while protecting keys or preparing the server certificate (DPAPI unavailable, no loadable user
/// profile for the key container) surface as <see cref="IdentityStoreException"/> with the cause inside, never with key
/// material, so the ASP.NET Core integration runs in its unavailable mode instead of stopping the host; and a renew or
/// reset that fails this way leaves the identity in force.
/// </summary>
[TestClass]
public sealed class PlatformFailureTests
{
    private const string Prefix = "/.well-known/gameshowpro";

    // The store

    [TestMethod]
    [DataRow(typeof(CryptographicException))]
    [DataRow(typeof(PlatformNotSupportedException))]
    [DataRow(typeof(InvalidOperationException))]
    public void Save_WhenTheProtectorFails_ThrowsIdentityStoreException_AndWritesNothing(Type failure)
    {
        using TempDirectory directory = new();
        FlakyProtector protector = new() { FailProtect = () => (Exception)Activator.CreateInstance(failure, "simulated")! };
        FileIdentityStore store = new(directory.Path, protector);
        using StoredIdentity identity = NewIdentity();

        IdentityStoreException exception = Assert.ThrowsExactly<IdentityStoreException>(() => store.Save(identity));

        Assert.IsInstanceOfType(exception.InnerException, failure);
        Assert.Contains("could not be protected", exception.Message);
        Assert.Contains(FlakyProtector.SchemeId, exception.Message);
        Assert.IsFalse(File.Exists(directory.IdentityFile));
        KeyMaterial.AssertAbsent(identity, exception.ToString());
    }

    [TestMethod]
    public void Save_WhenTheProtectorIsCanceled_DoesNotWrapIt()
    {
        using TempDirectory directory = new();
        FlakyProtector protector = new() { FailProtect = () => new OperationCanceledException() };
        using StoredIdentity identity = NewIdentity();

        _ = Assert.ThrowsExactly<OperationCanceledException>(() => new FileIdentityStore(directory.Path, protector).Save(identity));
    }

    [TestMethod]
    [DataRow(typeof(CryptographicException))]
    [DataRow(typeof(InvalidOperationException))]
    public void Load_WhenTheProtectorFails_ThrowsIdentityStoreException(Type failure)
    {
        using TempDirectory directory = new();
        FlakyProtector protector = new();
        FileIdentityStore store = new(directory.Path, protector);
        using StoredIdentity identity = NewIdentity();
        store.Save(identity);
        protector.FailUnprotect = () => (Exception)Activator.CreateInstance(failure, "simulated")!;

        IdentityStoreException exception = Assert.ThrowsExactly<IdentityStoreException>(store.Load);

        Assert.IsInstanceOfType(exception.InnerException, failure);
        Assert.Contains("cannot be decrypted", exception.Message);
        KeyMaterial.AssertAbsent(identity, exception.ToString());
    }

    // The manager

    [TestMethod]
    public async Task LoadOrCreate_WhenTheServerCertificateCannotBePrepared_ThrowsIdentityStoreException_AndLoadsNothing()
    {
        using TempDirectory directory = new();
        using (TlsIdentityManager healthy = TestManagers.Create(directory.CreateStore(), TimeProvider.System))
        {
            _ = await healthy.LoadOrCreate();
        }

        CollectingLogger logger = new();
        using TlsIdentityManager manager = TestManagers.Create(
            directory.CreateStore(),
            TimeProvider.System,
            configure: options => options.ServerCertificateFactoryOverride = FailingFactory,
            logger: logger);

        IdentityStoreException exception = await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => await manager.LoadOrCreate());

        _ = Assert.IsInstanceOfType<CryptographicException>(exception.InnerException);
        Assert.Contains("server certificate could not be prepared", exception.Message);
        Assert.IsFalse(manager.IsLoaded);
        Assert.AreEqual(exception.Message, manager.LoadFailure);
        Assert.HasCount(1, logger.Entries.Where(entry => entry.StartsWith("Error", StringComparison.Ordinal)));
        using StoredIdentity stored = directory.CreateStore().Load()!;
        KeyMaterial.AssertAbsent(stored, exception.ToString() + logger.AllText);
    }

    [TestMethod]
    public async Task LoadOrCreate_FirstRun_WhenTheServerCertificateCannotBePrepared_SavesNothing()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(
            directory.CreateStore(),
            TimeProvider.System,
            configure: options => options.ServerCertificateFactoryOverride = FailingFactory);

        IdentityStoreException exception = await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => await manager.LoadOrCreate());

        _ = Assert.IsInstanceOfType<CryptographicException>(exception.InnerException);
        Assert.IsFalse(manager.IsLoaded);
        Assert.IsFalse(File.Exists(directory.IdentityFile), "Nothing is saved that could not be served.");
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RenewAndReset_WhenTheServerCertificateCannotBePrepared_LeaveTheIdentityInForce(bool reset)
    {
        using TempDirectory directory = new();
        bool fail = false;
        using TlsIdentityManager manager = TestManagers.Create(
            directory.CreateStore(),
            TimeProvider.System,
            configure: options => options.ServerCertificateFactoryOverride = (leaf, key) => fail ? FailingFactory(leaf, key) : RealFactory(leaf, key));
        TlsIdentity before = await manager.LoadOrCreate();
        X509Certificate2 serverBefore = manager.CurrentServerCertificate;
        byte[] fileBefore = File.ReadAllBytes(directory.IdentityFile);
        int changes = 0;
        manager.Changed += (_, _) => changes++;
        fail = true;

        IdentityStoreException exception = await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => _ = reset ? await manager.ResetIdentity() : await manager.RenewLeaf());

        _ = Assert.IsInstanceOfType<CryptographicException>(exception.InnerException);
        Assert.AreSame(before, manager.Current);
        Assert.AreSame(serverBefore, manager.CurrentServerCertificate);
        CollectionAssert.AreEqual(fileBefore, File.ReadAllBytes(directory.IdentityFile));
        Assert.AreEqual(0, changes);
    }

    [TestMethod]
    public async Task Renew_WhenTheProtectorFails_LeavesTheIdentityInForce()
    {
        using TempDirectory directory = new();
        FlakyProtector protector = new();
        using TlsIdentityManager manager = TestManagers.Create(new FileIdentityStore(directory.Path, protector), TimeProvider.System);
        TlsIdentity before = await manager.LoadOrCreate();
        protector.FailProtect = () => new CryptographicException("simulated");

        IdentityStoreException exception = await Assert.ThrowsExactlyAsync<IdentityStoreException>(async () => await manager.RenewLeaf());

        _ = Assert.IsInstanceOfType<CryptographicException>(exception.InnerException);
        Assert.AreSame(before, manager.Current);
    }

    // The ASP.NET Core integration

    [TestMethod]
    public async Task Integration_WhenTheProtectorFails_StartsUnavailable_AndAResetThatFailsTheSameWayIs500()
    {
        FlakyProtector protector = new() { FailProtect = () => new CryptographicException("simulated DPAPI failure") };
        await using TestApp app = await TestApp.Start(options => options.KeyProtectorOverride = protector);
        ITlsCaStatus status = app.Status;
        int changed = 0;
        status.Changed += (_, _) => changed++;

        Assert.IsNotNull(status.IdentityProblem);
        Assert.Contains("could not be protected", status.IdentityProblem);
        await AssertUnavailable(app);

        using HttpResponseMessage failed = await app.PostJson(Prefix + "/reset");
        Assert.AreEqual(HttpStatusCode.InternalServerError, failed.StatusCode);
        Assert.IsNotNull(status.IdentityProblem);
        Assert.AreEqual(0, changed);
        await AssertUnavailable(app);

        // Once the platform cooperates, a reset recovers without a restart.
        protector.FailProtect = null;
        using HttpResponseMessage recovered = await app.PostJson(Prefix + "/reset");
        Assert.AreEqual(HttpStatusCode.OK, recovered.StatusCode);
        Assert.IsNull(status.IdentityProblem);
        Assert.AreEqual(1, changed);
    }

    [TestMethod]
    public async Task Integration_WhenTheServerCertificateCannotBePrepared_StartsUnavailable_AndAResetThatFailsTheSameWayIs500()
    {
        bool fail = true;
        byte[]? fileBefore = null;
        await using TestApp app = await TestApp.Start(
            options => options.ServerCertificateFactoryOverride = (leaf, key) => fail ? FailingFactory(leaf, key) : RealFactory(leaf, key),
            prepareStorage: PrepareHealthyIdentity);
        ITlsCaStatus status = app.Status;

        void PrepareHealthyIdentity(string path)
        {
            // A healthy identity on disk: only preparing it for serving fails.
            using TlsIdentityManager healthy = TestManagers.Create(new FileIdentityStore(path, FileIdentityStore.DefaultKeyProtector()), TimeProvider.System);
            _ = healthy.LoadOrCreate().AsTask().GetAwaiter().GetResult();
            fileBefore = File.ReadAllBytes(Path.Combine(path, FileIdentityStore.FileName));
        }

        Assert.IsNotNull(status.IdentityProblem);
        Assert.Contains("server certificate could not be prepared", status.IdentityProblem);
        Assert.AreEqual("", status.MdnsName);
        await AssertUnavailable(app);

        using HttpResponseMessage failed = await app.PostJson(Prefix + "/reset");
        Assert.AreEqual(HttpStatusCode.InternalServerError, failed.StatusCode);
        Assert.IsNotNull(status.IdentityProblem);
        CollectionAssert.AreEqual(fileBefore, File.ReadAllBytes(Path.Combine(app.StorageDirectory, FileIdentityStore.FileName)));
        await AssertUnavailable(app);

        fail = false;
        using HttpResponseMessage recovered = await app.PostJson(Prefix + "/reset");
        Assert.AreEqual(HttpStatusCode.OK, recovered.StatusCode);
        Assert.IsNull(status.IdentityProblem);
        using HttpResponseMessage ca = await app.Get(Prefix + "/ca.crt");
        Assert.AreEqual(HttpStatusCode.OK, ca.StatusCode);
    }

    private static async Task AssertUnavailable(TestApp app)
    {
        using HttpResponseMessage page = await app.Get(Prefix + "/");
        Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
        foreach (string path in new[] { "/info.json", "/ca.crt", "/ca.pem", "/ca.mobileconfig" })
        {
            using HttpResponseMessage response = await app.Get(Prefix + path);
            Assert.AreEqual(HttpStatusCode.ServiceUnavailable, response.StatusCode, path);
            Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString(), path);
        }

        using HttpResponseMessage renew = await app.PostJson(Prefix + "/renew");
        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, renew.StatusCode);
    }

    private static StoredIdentity NewIdentity()
    {
        using DeviceIdentity device = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        return new()
        {
            Name = TestPki.Name,
            CaCertificateDer = device.Ca.RawData,
            CaPrivateKeyPkcs8 = device.CaKey.ExportPkcs8PrivateKey(),
            LeafCertificateDer = device.Leaf.RawData,
            LeafPrivateKeyPkcs8 = device.LeafKey.ExportPkcs8PrivateKey(),
        };
    }

    private static X509Certificate2 FailingFactory(X509Certificate2 leaf, ECDsa key) =>
        throw new CryptographicException("Simulated: the key container could not be created (no loadable user profile).");

    private static X509Certificate2 RealFactory(X509Certificate2 leaf, ECDsa key) => ServerCertificateFactory.Create(leaf, key);

    /// <summary>A pass-through protector whose operations can be made to fail.</summary>
    private sealed class FlakyProtector : IKeyProtector
    {
        public const string SchemeId = "flaky-test";

        public Func<Exception>? FailProtect { get; set; }

        public Func<Exception>? FailUnprotect { get; set; }

        public string Id => SchemeId;

        public byte[] Protect(byte[] plaintext) => FailProtect is { } fail ? throw fail() : [.. plaintext];

        public byte[] Unprotect(byte[] protectedData) => FailUnprotect is { } fail ? throw fail() : [.. protectedData];
    }
}
