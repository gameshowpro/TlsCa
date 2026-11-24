namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Acceptance tests 3 and 4: chain validation with the platform's own validator (CryptoAPI on Windows, OpenSSL on
/// Linux), trusting only the device CA, revocation off, at a fixed time inside every certificate's validity.
/// </summary>
[TestClass]
public sealed class ChainTests
{
    [TestMethod]
    public void Leaf_ValidatesAgainstCaForItsName()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);

        (bool valid, X509ChainStatusFlags flags, int length) = TestPki.Validate(identity.Ca, identity.Leaf);

        Assert.AreEqual(X509ChainStatusFlags.NoError, flags);
        Assert.IsTrue(valid);
        Assert.AreEqual(2, length);
        Assert.IsTrue(identity.Leaf.MatchesHostname(TestPki.MdnsName, allowWildcards: false, allowCommonName: false));
        Assert.IsFalse(identity.Leaf.MatchesHostname("other-device.local", allowWildcards: false, allowCommonName: false));
    }

    [TestMethod]
    public void Leaf_DoesNotValidateAgainstAnotherDevicesCa()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using DeviceIdentity other = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);

        (bool valid, X509ChainStatusFlags flags, _) = TestPki.Validate(other.Ca, identity.Leaf);

        Assert.IsFalse(valid);
        Assert.AreNotEqual(X509ChainStatusFlags.NoError, flags);
    }

    [TestMethod]
    public void ArbitraryCertificateForTheDevicesOwnName_Validates()
    {
        // Control for the rejection tests below: the test signer produces certificates the validator accepts,
        // so a rejection there is caused by the name and nothing else.
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using X509Certificate2 forged = TestPki.SignArbitrary(identity.Ca, identity.CaKey, TestPki.MdnsName, n => n.AddDnsName(TestPki.MdnsName));

        (bool valid, X509ChainStatusFlags flags, _) = TestPki.Validate(identity.Ca, forged);

        Assert.AreEqual(X509ChainStatusFlags.NoError, flags);
        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DataRow("other-device.local", DisplayName = "Another .local name")]
    [DataRow("evilstudio-pc-triggergate.local", DisplayName = "Same suffix without a label boundary")]
    [DataRow("studio-pc-triggergate.example", DisplayName = "Same label in another domain")]
    public void CertificateForAnotherName_FailsOnNameConstraints(string dnsName)
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using X509Certificate2 forged = TestPki.SignArbitrary(identity.Ca, identity.CaKey, dnsName, n => n.AddDnsName(dnsName));

        AssertRejectedForNameConstraints(identity.Ca, forged);
    }

    [TestMethod]
    [DataRow("192.168.1.10", DisplayName = "IPv4")]
    [DataRow("fd00::10", DisplayName = "IPv6")]
    public void CertificateForAnIpAddress_FailsOnNameConstraints(string address)
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using X509Certificate2 forged = TestPki.SignArbitrary(identity.Ca, identity.CaKey, address, n => n.AddIpAddress(IPAddress.Parse(address)));

        AssertRejectedForNameConstraints(identity.Ca, forged);
    }

    [TestMethod]
    public void CertificateForTheDevicesNameWithAnIpAddress_FailsOnNameConstraints()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using X509Certificate2 forged = TestPki.SignArbitrary(identity.Ca, identity.CaKey, TestPki.MdnsName, AddDnsAndIpNames);

        AssertRejectedForNameConstraints(identity.Ca, forged);

        static void AddDnsAndIpNames(SubjectAlternativeNameBuilder n)
        {
            n.AddDnsName(TestPki.MdnsName);
            n.AddIpAddress(IPAddress.Parse("192.168.1.10"));
        }
    }

    private static void AssertRejectedForNameConstraints(X509Certificate2 ca, X509Certificate2 forged)
    {
        (bool valid, X509ChainStatusFlags flags, int length) = TestPki.Validate(ca, forged);

        Assert.IsFalse(valid, $"The platform validator accepted a certificate outside the CA's name constraints (flags: {flags}).");
        Assert.AreEqual(2, length, "The chain reached the device CA.");
        Assert.AreNotEqual(X509ChainStatusFlags.NoError, flags & TestPki.NameConstraintViolations, $"Expected a name-constraint failure, got {flags}.");
        Assert.AreEqual(X509ChainStatusFlags.NoError, flags & ~TestPki.NameConstraintViolations, $"Expected only name-constraint failures, got {flags}.");
    }
}
