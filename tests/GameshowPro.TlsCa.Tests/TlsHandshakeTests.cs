namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Acceptance test 8: a real <see cref="SslStream"/> server and client over loopback TCP. The server picks its
/// certificate per handshake from <see cref="TlsIdentityManager.CurrentServerCertificate"/>, as Kestrel's
/// <c>ServerCertificateSelector</c> does. The client trusts only the device CA and validates <c>&lt;name&gt;.local</c>.
/// </summary>
[TestClass]
public sealed class TlsHandshakeTests
{
    [TestMethod]
    [DataRow(SslProtocols.Tls12)]
    [DataRow(SslProtocols.Tls13)]
    public async Task ClientTrustingOnlyTheCa_GetsExactlyTheLeaf_AndARenewedLeafWithoutAListenerRestart(SslProtocols protocol)
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), TimeProvider.System);
        TlsIdentity identity = await manager.LoadOrCreate();
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(identity.CaCertificateDer.AsSpan());
        await using LoopbackTlsServer server = LoopbackTlsServer.WithSelector(() => manager.CurrentServerCertificate);

        HandshakeResult first = await server.Connect(identity.MdnsName, ca, protocol);

        AssertTrustedConnection(first, protocol, server);
        CollectionAssert.AreEqual(identity.LeafCertificateDer.ToArray(), first.Leaf, "The server sent the current leaf.");
        Assert.IsEmpty(first.AlsoSent, "The server sends the leaf only, not the CA.");

        TlsIdentity renewed = await manager.RenewLeaf();
        HandshakeResult second = await server.Connect(identity.MdnsName, ca, protocol);

        AssertTrustedConnection(second, protocol, server);
        CollectionAssert.AreEqual(renewed.LeafCertificateDer.ToArray(), second.Leaf, "The next connection gets the renewed leaf.");
        CollectionAssert.AreNotEqual(first.Leaf, second.Leaf);
        Assert.IsEmpty(second.AlsoSent);
        Assert.AreEqual(2, server.Accepted, "Both connections went to the same listener, which was never restarted.");
        Assert.IsEmpty(server.Failures);
    }

    [TestMethod]
    public async Task ClientForAnotherName_IsRejected()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), TimeProvider.System);
        TlsIdentity identity = await manager.LoadOrCreate();
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(identity.CaCertificateDer.AsSpan());
        await using LoopbackTlsServer server = LoopbackTlsServer.WithSelector(() => manager.CurrentServerCertificate);

        HandshakeResult result = await server.Connect("other-device.local", ca, SslProtocols.Tls13);

        Assert.IsFalse(result.Connected);
        Assert.AreEqual(SslPolicyErrors.RemoteCertificateNameMismatch, result.Errors);
    }

    [TestMethod]
    public async Task AfterAReset_ClientsTrustingTheOldCaAreRejectedAndTheNewCaWorks()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), TimeProvider.System);
        TlsIdentity original = await manager.LoadOrCreate();
        using X509Certificate2 oldCa = X509CertificateLoader.LoadCertificate(original.CaCertificateDer.AsSpan());
        await using LoopbackTlsServer server = LoopbackTlsServer.WithSelector(() => manager.CurrentServerCertificate);
        AssertTrustedConnection(await server.Connect(original.MdnsName, oldCa, SslProtocols.Tls13), SslProtocols.Tls13, server);

        TlsIdentity reset = await manager.ResetIdentity();
        using X509Certificate2 newCa = X509CertificateLoader.LoadCertificate(reset.CaCertificateDer.AsSpan());

        HandshakeResult withOldCa = await server.Connect(reset.MdnsName, oldCa, SslProtocols.Tls13);
        Assert.IsFalse(withOldCa.Connected);
        Assert.AreEqual(SslPolicyErrors.RemoteCertificateChainErrors, withOldCa.Errors);
        HandshakeResult withNewCa = await server.Connect(reset.MdnsName, newCa, SslProtocols.Tls13);
        AssertTrustedConnection(withNewCa, SslProtocols.Tls13, server);
        CollectionAssert.AreEqual(reset.LeafCertificateDer.ToArray(), withNewCa.Leaf);
    }

    [TestMethod]
    public async Task HandshakesDuringRepeatedRenewals_AllSucceed()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), TimeProvider.System);
        TlsIdentity identity = await manager.LoadOrCreate();
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(identity.CaCertificateDer.AsSpan());
        await using LoopbackTlsServer server = LoopbackTlsServer.WithSelector(() => manager.CurrentServerCertificate);
        HashSet<string> issued = [identity.LeafFingerprintSha256];
        using CancellationTokenSource renewalsDone = new();

        Task<List<HandshakeResult>>[] clients = [.. Enumerable.Range(0, 3).Select(_ => Task.Run(() => ConnectUntil(renewalsDone.Token)))];
        for (int i = 0; i < 10; i++)
        {
            _ = issued.Add((await manager.RenewLeaf()).LeafFingerprintSha256);
            await Task.Delay(20);
        }

        await renewalsDone.CancelAsync();
        HandshakeResult[] results = [.. (await Task.WhenAll(clients)).SelectMany(list => list)];

        Assert.IsGreaterThan(10, results.Length);
        foreach (HandshakeResult result in results)
        {
            AssertTrustedConnection(result, SslProtocols.Tls13, server);
            Assert.Contains(Fingerprint.Sha256(result.Leaf), issued);
            Assert.IsEmpty(result.AlsoSent);
        }

        async Task<List<HandshakeResult>> ConnectUntil(CancellationToken stop)
        {
            List<HandshakeResult> results = [];
            do
            {
                results.Add(await server.Connect(identity.MdnsName, ca, SslProtocols.Tls13));
            }
            while (!stop.IsCancellationRequested);
            return results;
        }
    }

    [TestMethod]
    // Not on Windows: there, a certificate context with an intermediate the machine cannot chain makes .NET add the
    // intermediate to the user's Intermediate Certification Authorities store, and nothing may be added to a store.
    [OSCondition(OperatingSystems.Linux)]
    public async Task ObservationControl_AServerThatSendsAnIntermediate_IsSeenSendingIt()
    {
        // Shows that the client really observes additional certificates, so "nothing else was sent" above is
        // meaningful. (.NET never sends a self-signed root, so the control needs an intermediate.)
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using ECDsa rootKey = CertificateProfiles.CreateKey();
        using ECDsa intermediateKey = CertificateProfiles.CreateKey();
        using ECDsa leafKey = CertificateProfiles.CreateKey();
        CertificateRequest rootRequest = new("CN=Control Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));
        CertificateRequest intermediateRequest = new("CN=Control Intermediate", intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
        intermediateRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        using X509Certificate2 intermediatePublic = intermediateRequest.Create(root, now.AddDays(-1), now.AddDays(20), [1, 2, 3, 4, 5, 6, 7, 8]);
        using X509Certificate2 intermediate = intermediatePublic.CopyWithPrivateKey(intermediateKey);
        CertificateRequest leafRequest = new("CN=control.local", leafKey, HashAlgorithmName.SHA256);
        SubjectAlternativeNameBuilder names = new();
        names.AddDnsName("control.local");
        leafRequest.CertificateExtensions.Add(names.Build());
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(CertificateProfiles.ServerAuthOid)], false));
        leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(intermediate, true, false));
        using X509Certificate2 leaf = leafRequest.Create(intermediate, now.AddDays(-1), now.AddDays(10), [8, 7, 6, 5, 4, 3, 2, 1]);
        using X509Certificate2 withKey = PersistedForTls(leaf, leafKey);
        SslStreamCertificateContext context = SslStreamCertificateContext.Create(withKey, [intermediatePublic], offline: true);
        await using LoopbackTlsServer server = LoopbackTlsServer.WithOptions(() => new() { ServerCertificateContext = context });

        HandshakeResult result = await server.Connect("control.local", root, SslProtocols.Tls13);

        AssertTrustedConnection(result, SslProtocols.Tls13, server);
        Assert.HasCount(1, result.AlsoSent);
        CollectionAssert.AreEqual(intermediatePublic.RawData, result.AlsoSent[0]);
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task Control_ALeafWithAnInMemoryKey_CannotBeServedBySChannel_OnWindows()
    {
        // Why the manager re-imports the leaf into a key container on Windows.
        using DeviceIdentity device = TestPki.CreateIdentity(TestPki.Name, DateTimeOffset.UtcNow);
        using X509Certificate2 ephemeral = device.Leaf.CopyWithPrivateKey(device.LeafKey);
        await using LoopbackTlsServer server = LoopbackTlsServer.WithSelector(() => ephemeral);

        HandshakeResult result = await server.Connect(TestPki.MdnsName, device.Ca, SslProtocols.Tls13);

        Assert.IsFalse(result.Connected);
    }

    [TestMethod]
    [DoNotParallelize]
    [OSCondition(OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public async Task ServerCertificateKey_LivesInAKeyContainerThatIsRemovedOnReplaceAndDispose_OnWindows()
    {
        string keys = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Crypto", "Keys");
        HashSet<string> before = KeyFiles(keys);
        using TempDirectory directory = new();
        TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), TimeProvider.System, retiredCertificateGrace: TimeSpan.FromMilliseconds(200));
        string firstKeyFile;
        string secondKeyFile;
        try
        {
            TlsIdentity identity = await manager.LoadOrCreate();
            firstKeyFile = KeyFileOf(manager.CurrentServerCertificate, keys);
            Assert.IsTrue(File.Exists(firstKeyFile), "The server key is in a key container in the account's profile.");
            Assert.IsFalse(before.Contains(firstKeyFile));

            // SChannel serves it.
            using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(identity.CaCertificateDer.AsSpan());
            await using (LoopbackTlsServer server = LoopbackTlsServer.WithSelector(() => manager.CurrentServerCertificate))
            {
                AssertTrustedConnection(await server.Connect(identity.MdnsName, ca, SslProtocols.Tls13), SslProtocols.Tls13, server);
            }

            _ = await manager.RenewLeaf();
            secondKeyFile = KeyFileOf(manager.CurrentServerCertificate, keys);
            Assert.AreNotEqual(firstKeyFile, secondKeyFile);
            Assert.IsTrue(File.Exists(firstKeyFile), "A replaced certificate stays usable for the grace period.");
            Assert.IsTrue(await WaitUntil(() => !File.Exists(firstKeyFile), TimeSpan.FromSeconds(10)), "The replaced certificate's key container is deleted after the grace period.");
            Assert.IsTrue(File.Exists(secondKeyFile));
        }
        finally
        {
            manager.Dispose();
        }

        Assert.IsFalse(File.Exists(secondKeyFile), "Disposing the manager deletes the current key container.");
        string[] leftBehind = [.. KeyFiles(keys).Except(before)];
        Assert.IsEmpty(leftBehind, $"Key containers left behind: {string.Join(", ", leftBehind)}");

        static HashSet<string> KeyFiles(string directory) =>
            Directory.Exists(directory) ? [.. Directory.GetFiles(directory)] : [];

        static string KeyFileOf(X509Certificate2 certificate, string directory)
        {
            using ECDsa key = certificate.GetECDsaPrivateKey()!;
            ECDsaCng cng = Assert.IsInstanceOfType<ECDsaCng>(key);
            Assert.IsFalse(cng.Key.IsEphemeral);
            Assert.IsFalse(cng.Key.IsMachineKey);
            Assert.AreEqual(CngProvider.MicrosoftSoftwareKeyStorageProvider, cng.Key.Provider);
            return Path.Combine(directory, cng.Key.UniqueName!);
        }
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Linux)]
    public async Task ServerCertificateKey_StaysInMemory_OnLinux()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), TimeProvider.System);
        TlsIdentity identity = await manager.LoadOrCreate();
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(identity.CaCertificateDer.AsSpan());
        await using LoopbackTlsServer server = LoopbackTlsServer.WithSelector(() => manager.CurrentServerCertificate);

        AssertTrustedConnection(await server.Connect(identity.MdnsName, ca, SslProtocols.Tls13), SslProtocols.Tls13, server);
        Assert.IsTrue(manager.CurrentServerCertificate.HasPrivateKey);
    }

    private static void AssertTrustedConnection(HandshakeResult result, SslProtocols protocol, LoopbackTlsServer server)
    {
        Assert.AreEqual(SslPolicyErrors.None, result.Errors, $"Server failures: {string.Join("; ", server.Failures.Select(f => f.Message))}");
        Assert.IsTrue(result.Connected, $"Server failures: {string.Join("; ", server.Failures.Select(f => f.Message))}");
        Assert.AreEqual(protocol, result.Protocol);
    }

    private static async Task<bool> WaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                return false;
            }

            await Task.Delay(50);
        }

        return true;
    }

    /// <summary>The leaf with its key in the form SChannel can serve (Windows key container); in memory elsewhere.</summary>
    private static X509Certificate2 PersistedForTls(X509Certificate2 leaf, ECDsa key)
    {
        X509Certificate2 withKey = leaf.CopyWithPrivateKey(key);
        if (!OperatingSystem.IsWindows())
        {
            return withKey;
        }

        using (withKey)
        {
            return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12, "control"), "control", X509KeyStorageFlags.UserKeySet);
        }
    }
}
