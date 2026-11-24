namespace GameshowPro.TlsCa.Tests;

/// <summary>Acceptance test 1: every field of both certificates matches the Part 1 profiles.</summary>
[TestClass]
public sealed class ProfileTests
{
    private const string EcdsaWithSha256Oid = "1.2.840.10045.4.3.2";
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string CommonNameOid = "2.5.4.3";
    private const string OrganizationOid = "2.5.4.10";
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string KeyUsageOid = "2.5.29.15";
    private const string ExtendedKeyUsageOid = "2.5.29.37";
    private const string SubjectKeyIdentifierOid = "2.5.29.14";
    private const string SubjectAlternativeNameOid = "2.5.29.17";
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";
    private const string NameConstraintsOid = "2.5.29.30";

    // DER of the secp256r1 named-curve OID.
    private static readonly byte[] s_p256Parameters = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // Hand-built extension values.
    private static readonly byte[] s_caBasicConstraints = [0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00]; // cA TRUE, pathLen 0
    private static readonly byte[] s_leafBasicConstraints = [0x30, 0x00]; // cA FALSE (default, omitted)
    private static readonly byte[] s_keyCertSignOnly = [0x03, 0x02, 0x02, 0x04]; // bit 5
    private static readonly byte[] s_digitalSignatureOnly = [0x03, 0x02, 0x07, 0x80]; // bit 0
    private static readonly byte[] s_serverAuthOnly = [0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

    [TestMethod]
    [DataRow("2026-11-22T10:30:15.750Z", "2026-11-20T10:30:15Z", "2046-11-20T10:30:15Z", "2029-01-28T10:30:15Z")]
    [DataRow("2001-03-04T05:06:07Z", "2001-03-02T05:06:07Z", "2021-03-02T05:06:07Z", "2003-05-11T05:06:07Z")]
    public void Validity_UsesSuppliedTime(string now, string notBefore, string caNotAfter, string leafNotAfter)
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, DateTimeOffset.Parse(now, CultureInfo.InvariantCulture));

        Assert.AreEqual(Utc(notBefore), identity.Ca.NotBefore.ToUniversalTime());
        Assert.AreEqual(Utc(caNotAfter), identity.Ca.NotAfter.ToUniversalTime());
        Assert.AreEqual(Utc(notBefore), identity.Leaf.NotBefore.ToUniversalTime());
        Assert.AreEqual(Utc(leafNotAfter), identity.Leaf.NotAfter.ToUniversalTime());

        // NotBefore and NotAfter are local times; compare in UTC so a daylight saving change does not count.
        TimeSpan leafSpan = identity.Leaf.NotAfter.ToUniversalTime() - identity.Leaf.NotBefore.ToUniversalTime();
        Assert.AreEqual(TimeSpan.FromDays(800), leafSpan);
        Assert.IsLessThanOrEqualTo(TimeSpan.FromDays(825), leafSpan);

        static DateTime Utc(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture).UtcDateTime;
    }

    [TestMethod]
    public void BothCertificates_AreV3EcdsaP256Sha256WithSeparateKeysAndRandomSerials()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        using DeviceIdentity other = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);

        foreach (X509Certificate2 certificate in new[] { identity.Ca, identity.Leaf })
        {
            Assert.AreEqual(3, certificate.Version);
            Assert.AreEqual(EcdsaWithSha256Oid, certificate.SignatureAlgorithm.Value);
            Assert.AreEqual(EcPublicKeyOid, certificate.PublicKey.Oid.Value);
            CollectionAssert.AreEqual(s_p256Parameters, certificate.PublicKey.EncodedParameters?.RawData);
            Assert.IsFalse(certificate.HasPrivateKey, "Profiles return certificates without private keys.");

            byte[] serial = certificate.SerialNumberBytes.ToArray();
            BigInteger value = new(serial, isUnsigned: false, isBigEndian: true);
            Assert.IsGreaterThan(BigInteger.Zero, value, "Serial numbers are positive.");
            Assert.IsGreaterThanOrEqualTo(64L, value.GetBitLength(), "Serial numbers have at least 64 bits.");
        }

        CollectionAssert.AreNotEqual(identity.Ca.PublicKey.EncodedKeyValue.RawData, identity.Leaf.PublicKey.EncodedKeyValue.RawData);
        CollectionAssert.AreNotEqual(identity.Ca.SerialNumberBytes.ToArray(), identity.Leaf.SerialNumberBytes.ToArray());
        CollectionAssert.AreNotEqual(identity.Ca.SerialNumberBytes.ToArray(), other.Ca.SerialNumberBytes.ToArray());
        CollectionAssert.AreNotEqual(identity.Leaf.SerialNumberBytes.ToArray(), other.Leaf.SerialNumberBytes.ToArray());
    }

    [TestMethod]
    public void CaCertificate_MatchesProfile()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        X509Certificate2 ca = identity.Ca;

        // Subject and issuer: CN=GameshowPro Device CA <name>, O=GameshowPro, self-issued.
        Assert.AreEqual($"CN=GameshowPro Device CA {TestPki.Name}, O=GameshowPro", ca.SubjectName.Name);
        AssertRdns(ca.SubjectName, (OrganizationOid, "GameshowPro"), (CommonNameOid, $"GameshowPro Device CA {TestPki.Name}"));
        CollectionAssert.AreEqual(ca.SubjectName.RawData, ca.IssuerName.RawData);

        Dictionary<string, X509Extension> extensions = ExtensionsByOid(ca);
        CollectionAssert.AreEquivalent(
            new[] { BasicConstraintsOid, KeyUsageOid, NameConstraintsOid, ExtendedKeyUsageOid, SubjectKeyIdentifierOid },
            extensions.Keys.ToArray());

        AssertExtension(extensions[BasicConstraintsOid], critical: true, s_caBasicConstraints);
        X509BasicConstraintsExtension basicConstraints = (X509BasicConstraintsExtension)extensions[BasicConstraintsOid];
        Assert.IsTrue(basicConstraints.CertificateAuthority);
        Assert.IsTrue(basicConstraints.HasPathLengthConstraint);
        Assert.AreEqual(0, basicConstraints.PathLengthConstraint);

        AssertExtension(extensions[KeyUsageOid], critical: true, s_keyCertSignOnly);
        Assert.AreEqual(X509KeyUsageFlags.KeyCertSign, ((X509KeyUsageExtension)extensions[KeyUsageOid]).KeyUsages);

        Assert.IsTrue(extensions[NameConstraintsOid].Critical);

        AssertExtension(extensions[ExtendedKeyUsageOid], critical: false, s_serverAuthOnly);

        X509SubjectKeyIdentifierExtension subjectKeyIdentifier = (X509SubjectKeyIdentifierExtension)extensions[SubjectKeyIdentifierOid];
        Assert.IsFalse(subjectKeyIdentifier.Critical);
        Assert.IsFalse(subjectKeyIdentifier.SubjectKeyIdentifierBytes.IsEmpty);

        // Self-signed: the CA's own key verifies its signature.
        (bool valid, X509ChainStatusFlags flags, _) = TestPki.Validate(ca, ca);
        Assert.AreEqual(X509ChainStatusFlags.NoError, flags);
        Assert.IsTrue(valid);
    }

    [TestMethod]
    public void LeafCertificate_MatchesProfile()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        X509Certificate2 leaf = identity.Leaf;

        Assert.AreEqual($"CN={TestPki.MdnsName}", leaf.SubjectName.Name);
        AssertRdns(leaf.SubjectName, (CommonNameOid, TestPki.MdnsName));

        // The issuer is byte-for-byte the CA subject, so chains build by name match.
        CollectionAssert.AreEqual(identity.Ca.SubjectName.RawData, leaf.IssuerName.RawData);

        Dictionary<string, X509Extension> extensions = ExtensionsByOid(leaf);
        CollectionAssert.AreEquivalent(
            new[] { BasicConstraintsOid, KeyUsageOid, ExtendedKeyUsageOid, SubjectAlternativeNameOid, AuthorityKeyIdentifierOid },
            extensions.Keys.ToArray());

        AssertExtension(extensions[BasicConstraintsOid], critical: true, s_leafBasicConstraints);
        Assert.IsFalse(((X509BasicConstraintsExtension)extensions[BasicConstraintsOid]).CertificateAuthority);

        AssertExtension(extensions[KeyUsageOid], critical: true, s_digitalSignatureOnly);
        Assert.AreEqual(X509KeyUsageFlags.DigitalSignature, ((X509KeyUsageExtension)extensions[KeyUsageOid]).KeyUsages);

        AssertExtension(extensions[ExtendedKeyUsageOid], critical: false, s_serverAuthOnly);

        // subjectAltName: exactly one GeneralName, a dNSName [2] holding <name>.local.
        X509Extension subjectAlternativeName = extensions[SubjectAlternativeNameOid];
        Assert.IsFalse(subjectAlternativeName.Critical);
        AsnReader outer = new(subjectAlternativeName.RawData, AsnEncodingRules.DER);
        AsnReader generalNames = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        Assert.AreEqual(TestPki.MdnsName, generalNames.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 2)));
        Assert.IsFalse(generalNames.HasData, "The subjectAltName holds exactly one name.");

        // authorityKeyIdentifier: keyIdentifier only, equal to the CA subjectKeyIdentifier.
        X509AuthorityKeyIdentifierExtension authorityKeyIdentifier = (X509AuthorityKeyIdentifierExtension)extensions[AuthorityKeyIdentifierOid];
        Assert.IsFalse(authorityKeyIdentifier.Critical);
        X509SubjectKeyIdentifierExtension caSubjectKeyIdentifier = identity.Ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single();
        Assert.IsTrue(authorityKeyIdentifier.KeyIdentifier.HasValue);
        CollectionAssert.AreEqual(caSubjectKeyIdentifier.SubjectKeyIdentifierBytes.ToArray(), authorityKeyIdentifier.KeyIdentifier.Value.ToArray());
        Assert.IsNull(authorityKeyIdentifier.NamedIssuer);
        Assert.IsFalse(authorityKeyIdentifier.SerialNumber.HasValue);
    }

    private static Dictionary<string, X509Extension> ExtensionsByOid(X509Certificate2 certificate) =>
        certificate.Extensions.ToDictionary(e => e.Oid!.Value!);

    private static void AssertExtension(X509Extension extension, bool critical, byte[] expectedValue)
    {
        Assert.AreEqual(critical, extension.Critical, $"Criticality of {extension.Oid?.Value}.");
        CollectionAssert.AreEqual(expectedValue, extension.RawData, $"Value of {extension.Oid?.Value}.");
    }

    private static void AssertRdns(X500DistinguishedName name, params (string Oid, string Value)[] expectedInEncodedOrder)
    {
        (string Oid, string Value)[] actual = [.. name.EnumerateRelativeDistinguishedNames(reversed: false)
            .Select(rdn => (rdn.HasMultipleElements ? "multi-valued" : rdn.GetSingleElementType().Value!, rdn.GetSingleElementValue() ?? ""))];
        CollectionAssert.AreEqual(expectedInEncodedOrder, actual);
    }
}
