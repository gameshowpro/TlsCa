namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Test-only PKI helpers. <see cref="SignArbitrary"/> signs certificates with the device CA key for names the library
/// would never issue, so the tests can check that the platform validator enforces the CA's name constraints. It lives
/// here, not in the library, so the library API can only ever issue a leaf for the device's own name.
/// </summary>
internal static class TestPki
{
    public const string Name = "studio-pc-triggergate";
    public const string MdnsName = Name + ".local";

    /// <summary>A fixed issuance time with a fractional second, which the profiles truncate.</summary>
    public static readonly DateTimeOffset Now = new DateTimeOffset(2026, 11, 22, 10, 30, 15, TimeSpan.Zero).AddMilliseconds(750);

    /// <summary>The name-constraint failures a validator may report for a name outside the CA's constraints.</summary>
    public const X509ChainStatusFlags NameConstraintViolations =
        X509ChainStatusFlags.HasNotPermittedNameConstraint | X509ChainStatusFlags.HasExcludedNameConstraint;

    public static DeviceIdentity CreateIdentity(string name, DateTimeOffset now)
    {
        ECDsa caKey = CertificateProfiles.CreateKey();
        X509Certificate2 ca = CertificateProfiles.CreateCa(name, caKey, now);
        ECDsa leafKey = CertificateProfiles.CreateKey();
        X509Certificate2 leaf = CertificateProfiles.CreateLeaf(name, ca, caKey, leafKey, now);
        return new(caKey, ca, leafKey, leaf);
    }

    public static X509Certificate2 SignArbitrary(
        X509Certificate2 caCertificate, ECDsa caKey, string commonName, Action<SubjectAlternativeNameBuilder> addNames)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X500DistinguishedNameBuilder subject = new();
        subject.AddCommonName(commonName);
        SubjectAlternativeNameBuilder names = new();
        addNames(names);

        CertificateRequest request = new(subject.Build(), key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(CertificateProfiles.ServerAuthOid)], false));
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(caCertificate, true, false));

        DateTimeOffset notBefore = Now.AddHours(-48);
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] = (byte)((serial[0] & 0x7F) | 0x40);
        return request.Create(caCertificate.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey), notBefore, notBefore.AddDays(800), serial);
    }

    /// <summary>
    /// Validates <paramref name="leaf"/> with the platform's chain engine, trusting only <paramref name="caCertificate"/>,
    /// revocation off, at <paramref name="at"/> (default <see cref="Now"/>), for server authentication. Returns every
    /// status flag on the chain and its elements.
    /// </summary>
    public static (bool Valid, X509ChainStatusFlags Flags, int Length) Validate(X509Certificate2 caCertificate, X509Certificate2 leaf, DateTimeOffset? at = null)
    {
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        _ = chain.ChainPolicy.CustomTrustStore.Add(caCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationTime = (at ?? Now).LocalDateTime;
        _ = chain.ChainPolicy.ApplicationPolicy.Add(new Oid(CertificateProfiles.ServerAuthOid));

        bool valid = chain.Build(leaf);
        X509ChainStatusFlags flags = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, (all, s) => all | s.Status);
        foreach (X509ChainElement element in chain.ChainElements)
        {
            flags = element.ChainElementStatus.Aggregate(flags, (all, s) => all | s.Status);
        }

        return (valid, flags, chain.ChainElements.Count);
    }
}

internal sealed class DeviceIdentity(ECDsa caKey, X509Certificate2 ca, ECDsa leafKey, X509Certificate2 leaf) : IDisposable
{
    public ECDsa CaKey { get; } = caKey;
    public X509Certificate2 Ca { get; } = ca;
    public ECDsa LeafKey { get; } = leafKey;
    public X509Certificate2 Leaf { get; } = leaf;

    public void Dispose()
    {
        CaKey.Dispose();
        Ca.Dispose();
        LeafKey.Dispose();
        Leaf.Dispose();
    }
}
