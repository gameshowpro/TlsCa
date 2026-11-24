namespace GameshowPro.TlsCa.Tests;

/// <summary>The profile builders refuse inputs that would produce a certificate outside the profiles.</summary>
[TestClass]
public sealed class CertificateProfilesGuardTests
{
    [TestMethod]
    [DataRow("Studio-PC")]
    [DataRow("studio.local")]
    [DataRow("")]
    public void CreateCa_InvalidName_Throws(string name)
    {
        using ECDsa key = CertificateProfiles.CreateKey();
        _ = Assert.ThrowsExactly<ArgumentException>(() => CertificateProfiles.CreateCa(name, key, TestPki.Now));
    }

    [TestMethod]
    public void CreateCa_NonP256Key_Throws()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        AssertThrowsWithoutKeyMaterial(key, () => CertificateProfiles.CreateCa(TestPki.Name, key, TestPki.Now));
    }

    [TestMethod]
    public void CreateLeaf_CaForAnotherName_Throws()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using ECDsa leafKey = CertificateProfiles.CreateKey();
        AssertThrowsWithoutKeyMaterial(identity.CaKey, () => CertificateProfiles.CreateLeaf("other-device", identity.Ca, identity.CaKey, leafKey, TestPki.Now));
    }

    [TestMethod]
    public void CreateLeaf_CaKeyNotMatchingCertificate_Throws()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using ECDsa wrongCaKey = CertificateProfiles.CreateKey();
        using ECDsa leafKey = CertificateProfiles.CreateKey();
        AssertThrowsWithoutKeyMaterial(wrongCaKey, () => CertificateProfiles.CreateLeaf(TestPki.Name, identity.Ca, wrongCaKey, leafKey, TestPki.Now));
    }

    [TestMethod]
    public void CreateLeaf_LeafKeySameAsCaKey_Throws()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        AssertThrowsWithoutKeyMaterial(identity.CaKey, () => CertificateProfiles.CreateLeaf(TestPki.Name, identity.Ca, identity.CaKey, identity.CaKey, TestPki.Now));
    }

    [TestMethod]
    public void CreateLeaf_NonP256LeafKey_Throws()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        AssertThrowsWithoutKeyMaterial(leafKey, () => CertificateProfiles.CreateLeaf(TestPki.Name, identity.Ca, identity.CaKey, leafKey, TestPki.Now));
    }

    [TestMethod]
    public void CreateLeaf_InTheCasFinal800Days_IsClampedToTheCaNotAfter()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using ECDsa leafKey = CertificateProfiles.CreateKey();
        DateTimeOffset late = TestPki.Now.AddYears(CertificateProfiles.CaLifetimeYears).AddDays(-799);

        using X509Certificate2 leaf = CertificateProfiles.CreateLeaf(TestPki.Name, identity.Ca, identity.CaKey, leafKey, late);

        Assert.AreEqual(identity.Ca.NotAfter.ToUniversalTime(), leaf.NotAfter.ToUniversalTime());
        DateTimeOffset expectedNotBefore = new DateTimeOffset(late.UtcTicks - (late.UtcTicks % TimeSpan.TicksPerSecond), TimeSpan.Zero).AddHours(-48);
        Assert.AreEqual(expectedNotBefore.UtcDateTime, leaf.NotBefore.ToUniversalTime());
        (bool valid, X509ChainStatusFlags flags, _) = TestPki.Validate(identity.Ca, leaf, late);
        Assert.AreEqual(X509ChainStatusFlags.NoError, flags);
        Assert.IsTrue(valid);
    }

    [TestMethod]
    public void CreateLeaf_OneSecondBeforeTheCaExpires_IsClamped()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using ECDsa leafKey = CertificateProfiles.CreateKey();
        DateTimeOffset late = new DateTimeOffset(identity.Ca.NotAfter.ToUniversalTime(), TimeSpan.Zero).AddSeconds(-1);

        using X509Certificate2 leaf = CertificateProfiles.CreateLeaf(TestPki.Name, identity.Ca, identity.CaKey, leafKey, late);

        Assert.AreEqual(identity.Ca.NotAfter.ToUniversalTime(), leaf.NotAfter.ToUniversalTime());
    }

    [TestMethod]
    public void CreateLeaf_AfterTheCaExpires_Throws()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using ECDsa leafKey = CertificateProfiles.CreateKey();
        DateTimeOffset expired = new(identity.Ca.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        AssertThrowsWithoutKeyMaterial(identity.CaKey, () => CertificateProfiles.CreateLeaf(TestPki.Name, identity.Ca, identity.CaKey, leafKey, expired));
    }

    [TestMethod]
    public void CreateLeaf_LastDayThatFitsInsideTheCa_IsNotClamped()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using ECDsa leafKey = CertificateProfiles.CreateKey();
        DateTimeOffset late = TestPki.Now.AddYears(CertificateProfiles.CaLifetimeYears).AddDays(-800);
        using X509Certificate2 leaf = CertificateProfiles.CreateLeaf(TestPki.Name, identity.Ca, identity.CaKey, leafKey, late);
        Assert.IsLessThanOrEqualTo(identity.Ca.NotAfter, leaf.NotAfter);
        Assert.AreEqual(TimeSpan.FromDays(800), leaf.NotAfter.ToUniversalTime() - leaf.NotBefore.ToUniversalTime());
    }

    private static void AssertThrowsWithoutKeyMaterial(ECDsa key, Action action)
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(action);
        byte[] privateScalar = key.ExportParameters(includePrivateParameters: true).D!;
        string text = exception.ToString();
        Assert.DoesNotContain(Convert.ToHexString(privateScalar), text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(privateScalar), text, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(key.ExportPkcs8PrivateKey()), text, StringComparison.Ordinal);
    }
}
