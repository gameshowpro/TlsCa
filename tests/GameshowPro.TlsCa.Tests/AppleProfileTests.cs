namespace GameshowPro.TlsCa.Tests;

/// <summary>Acceptance test 10: well-formed plist, the CA in DER, UUIDs stable across calls and changed by a reset.</summary>
[TestClass]
public sealed class AppleProfileTests
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 22, 10, 30, 15, TimeSpan.Zero);

    [TestMethod]
    public async Task Build_IsAWellFormedUnsignedProfileWithOneRootPayloadHoldingTheCaInDer()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), new ManualTimeProvider(s_now));
        TlsIdentity identity = await manager.LoadOrCreate();

        byte[] profile = AppleProfile.Build(identity);

        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(profile));
        Assert.AreEqual("plist", document.Root!.Name.LocalName);
        Assert.AreEqual("1.0", (string?)document.Root.Attribute("version"));
        Assert.AreEqual("-//Apple//DTD PLIST 1.0//EN", document.DocumentType?.PublicId);
        Assert.AreEqual(0, profile.AsSpan().IndexOf("<?xml"u8));
        Dictionary<string, XElement> root = ReadDict(document.Root.Element("dict")!);
        Assert.AreEqual("Configuration", root["PayloadType"].Value);
        Assert.AreEqual(1, int.Parse(root["PayloadVersion"].Value, CultureInfo.InvariantCulture));
        Assert.AreEqual("GameshowPro", root["PayloadOrganization"].Value);
        Assert.AreEqual("com.gameshowpro.tlsca." + identity.Name, root["PayloadIdentifier"].Value);
        Assert.IsTrue(Guid.TryParse(root["PayloadUUID"].Value, out _));

        XElement[] payloads = [.. root["PayloadContent"].Elements("dict")];
        Assert.HasCount(1, payloads);
        Dictionary<string, XElement> payload = ReadDict(payloads[0]);
        Assert.AreEqual("com.apple.security.root", payload["PayloadType"].Value);
        Assert.AreEqual("com.gameshowpro.tlsca." + identity.Name + ".ca", payload["PayloadIdentifier"].Value);
        Assert.AreNotEqual(root["PayloadUUID"].Value, payload["PayloadUUID"].Value);
        Assert.IsTrue(Guid.TryParse(payload["PayloadUUID"].Value, out _));
        Assert.AreEqual("data", payload["PayloadContent"].Name.LocalName);
        byte[] der = Convert.FromBase64String(payload["PayloadContent"].Value);
        CollectionAssert.AreEqual(identity.CaCertificateDer.ToArray(), der);
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(der);
        Assert.AreEqual(identity.CaFingerprintSha256, Fingerprint.Sha256(ca));
    }

    [TestMethod]
    public async Task Build_UuidsAreStableAcrossCalls_AndChangedByAReset()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), new ManualTimeProvider(s_now));
        TlsIdentity first = await manager.LoadOrCreate();

        byte[] one = AppleProfile.Build(first);
        byte[] two = AppleProfile.Build(first);
        TlsIdentity renewed = await manager.RenewLeaf();
        byte[] afterRenew = AppleProfile.Build(renewed);
        TlsIdentity reset = await manager.ResetIdentity();
        byte[] afterReset = AppleProfile.Build(reset);

        CollectionAssert.AreEqual(one, two);
        CollectionAssert.AreEqual(one, afterRenew, "A leaf renewal does not change the CA, so it must not change the profile.");
        string[] uuids = Uuids(one);
        string[] resetUuids = Uuids(afterReset);
        Assert.HasCount(2, uuids);
        Assert.AreNotEqual(uuids[0], uuids[1]);
        Assert.AreNotEqual(uuids[0], resetUuids[0]);
        Assert.AreNotEqual(uuids[1], resetUuids[1]);
    }

    [TestMethod]
    public async Task Build_IdentifiersAreUniquePerDevice()
    {
        using TempDirectory first = new();
        using TempDirectory second = new();
        using TlsIdentityManager one = TestManagers.Create(first.CreateStore(), new ManualTimeProvider(s_now), () => "Studio A");
        using TlsIdentityManager two = TestManagers.Create(second.CreateStore(), new ManualTimeProvider(s_now), () => "Studio B");

        string[] identifiersOne = Identifiers(AppleProfile.Build(await one.LoadOrCreate()));
        string[] identifiersTwo = Identifiers(AppleProfile.Build(await two.LoadOrCreate()));

        Assert.AreEqual(0, identifiersOne.Intersect(identifiersTwo).Count());
        Assert.IsTrue(identifiersOne.All(identifier => identifier.StartsWith("com.gameshowpro.tlsca.studio-a-triggergate", StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task Build_ContainsNoPrivateKeyMaterial()
    {
        using TempDirectory directory = new();
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), new ManualTimeProvider(s_now));
        TlsIdentity identity = await manager.LoadOrCreate();

        HttpSurfaceTests.AssertNoKeys(directory.CreateStore().Load()!, AppleProfile.Build(identity));
    }

    private static Dictionary<string, XElement> ReadDict(XElement dict)
    {
        XElement[] children = [.. dict.Elements()];
        Assert.AreEqual(0, children.Length % 2);
        Dictionary<string, XElement> result = [];
        for (int i = 0; i < children.Length; i += 2)
        {
            Assert.AreEqual("key", children[i].Name.LocalName);
            result.Add(children[i].Value, children[i + 1]);
        }

        return result;
    }

    private static string[] Uuids(byte[] profile)
    {
        XElement dict = XDocument.Parse(Encoding.UTF8.GetString(profile)).Root!.Element("dict")!;
        Dictionary<string, XElement> root = ReadDict(dict);
        Dictionary<string, XElement> payload = ReadDict(root["PayloadContent"].Element("dict")!);
        return [root["PayloadUUID"].Value, payload["PayloadUUID"].Value];
    }

    private static string[] Identifiers(byte[] profile)
    {
        Dictionary<string, XElement> root = ReadDict(XDocument.Parse(Encoding.UTF8.GetString(profile)).Root!.Element("dict")!);
        Dictionary<string, XElement> payload = ReadDict(root["PayloadContent"].Element("dict")!);
        return [root["PayloadIdentifier"].Value, payload["PayloadIdentifier"].Value];
    }
}
