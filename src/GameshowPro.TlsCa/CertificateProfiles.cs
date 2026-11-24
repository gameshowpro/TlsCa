namespace GameshowPro.TlsCa;

/// <summary>
/// Builds the device CA and leaf certificates exactly to the profiles in the TLS CA specification: ECDSA P-256 with
/// SHA-256, random positive 128-bit serial numbers, a name-constrained CA and a leaf for one <c>.local</c> name.
/// Time is always supplied by the caller; nothing here reads the clock.
/// </summary>
/// <remarks>
/// The certificates returned carry no private key. The caller already holds the keys and decides where the leaf key
/// is combined with its certificate. Exceptions never include key material.
/// </remarks>
public static class CertificateProfiles
{
    /// <summary>notBefore of both certificates is the issuance time minus this, to tolerate wrong clocks on offline clients.</summary>
    public static readonly TimeSpan Backdate = TimeSpan.FromHours(48);

    /// <summary>The leaf's notAfter is its notBefore plus this. Apple platforms enforce at most 825 days.</summary>
    public static readonly TimeSpan LeafLifetime = TimeSpan.FromDays(800);

    /// <summary>The CA's notAfter is its notBefore plus this many years.</summary>
    public const int CaLifetimeYears = 20;

    /// <summary>id-kp-serverAuth.</summary>
    public const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>id-ce-nameConstraints.</summary>
    public const string NameConstraintsOid = "2.5.29.30";

    /// <summary>The organization in every device CA subject.</summary>
    public const string Organization = "GameshowPro";

    /// <summary>The device CA common name is this prefix followed by the device name.</summary>
    public const string CaCommonNamePrefix = "GameshowPro Device CA ";

    private const int SerialNumberLength = 16;

    // id-ecPublicKey and the DER encoding of the secp256r1 (P-256) curve OID, 1.2.840.10045.3.1.7.
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private static readonly ImmutableArray<byte> s_p256CurveParameters = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    /// <summary>Generates a new ECDSA P-256 key pair. The caller owns and disposes it.</summary>
    public static ECDsa CreateKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>The device CA subject (and issuer): <c>CN=GameshowPro Device CA &lt;name&gt;, O=GameshowPro</c>.</summary>
    public static X500DistinguishedName CaSubject(string name)
    {
        DeviceName.ThrowIfInvalid(name);
        // The builder encodes attributes in the reverse order of the calls, matching the string form, so the DER
        // order is O then CN (most significant first), which OpenSSL prints as "O = GameshowPro, CN = ...".
        X500DistinguishedNameBuilder builder = new();
        builder.AddCommonName(CaCommonNamePrefix + name);
        builder.AddOrganizationName(Organization);
        return builder.Build();
    }

    /// <summary>The leaf subject: <c>CN=&lt;name&gt;.local</c>.</summary>
    public static X500DistinguishedName LeafSubject(string name)
    {
        X500DistinguishedNameBuilder builder = new();
        builder.AddCommonName(DeviceName.ToMdnsName(name));
        return builder.Build();
    }

    /// <summary>
    /// Creates the self-signed device CA certificate for <paramref name="name"/>, signed with <paramref name="caKey"/>.
    /// notBefore is <paramref name="now"/> minus <see cref="Backdate"/> (whole seconds); notAfter is notBefore plus
    /// <see cref="CaLifetimeYears"/> years.
    /// </summary>
    /// <param name="name">The device name (a single DNS label, without <c>.local</c>).</param>
    /// <param name="caKey">The device CA key pair; must be ECDSA P-256.</param>
    /// <param name="now">The issuance time.</param>
    /// <returns>The CA certificate, without its private key.</returns>
    public static X509Certificate2 CreateCa(string name, ECDsa caKey, DateTimeOffset now)
    {
        X500DistinguishedName subject = CaSubject(name);
        ArgumentNullException.ThrowIfNull(caKey);
        ThrowIfNotP256(caKey);

        DateTimeOffset notBefore = WholeSeconds(now) - Backdate;
        DateTimeOffset notAfter = notBefore.AddYears(CaLifetimeYears);

        CertificateRequest request = new(subject, caKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, critical: true));
        request.CertificateExtensions.Add(new X509Extension(
            NameConstraintsOid, EncodeNameConstraints(DeviceName.ToMdnsName(name)), critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid)], critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        return request.Create(subject, X509SignatureGenerator.CreateForECDsa(caKey), notBefore, notAfter, NewSerialNumber());
    }

    /// <summary>
    /// Creates a leaf certificate for <c>&lt;name&gt;.local</c> holding the public half of <paramref name="leafKey"/>,
    /// signed by the device CA. notBefore is <paramref name="now"/> minus <see cref="Backdate"/> (whole seconds);
    /// notAfter is notBefore plus <see cref="LeafLifetime"/>, clamped to the CA's notAfter when the CA expires sooner
    /// (a leaf never outlives its CA). The only name in the certificate is the device's own.
    /// </summary>
    /// <param name="name">The device name (a single DNS label, without <c>.local</c>). It must be the CA's name.</param>
    /// <param name="caCertificate">The device CA certificate for <paramref name="name"/>, as made by <see cref="CreateCa"/>.</param>
    /// <param name="caKey">The private key of <paramref name="caCertificate"/>.</param>
    /// <param name="leafKey">The leaf key pair; must be ECDSA P-256 and differ from the CA key.</param>
    /// <param name="now">The issuance time.</param>
    /// <returns>The leaf certificate, without its private key.</returns>
    /// <exception cref="ArgumentException">
    /// The CA certificate is not the device CA for <paramref name="name"/>, the CA key does not match it, a key is not
    /// P-256, the leaf key is the CA key, or the CA has expired at <paramref name="now"/>.
    /// </exception>
    public static X509Certificate2 CreateLeaf(string name, X509Certificate2 caCertificate, ECDsa caKey, ECDsa leafKey, DateTimeOffset now)
    {
        X500DistinguishedName subject = LeafSubject(name);
        ArgumentNullException.ThrowIfNull(caCertificate);
        ArgumentNullException.ThrowIfNull(caKey);
        ArgumentNullException.ThrowIfNull(leafKey);
        ThrowIfNotP256(caKey);
        ThrowIfNotP256(leafKey);

        if (!caCertificate.SubjectName.RawData.AsSpan().SequenceEqual(CaSubject(name).RawData))
        {
            throw new ArgumentException("The CA certificate is not the device CA for this device name.", nameof(caCertificate));
        }

        byte[] caPublicKey = caKey.ExportSubjectPublicKeyInfo();
        if (!caPublicKey.AsSpan().SequenceEqual(caCertificate.PublicKey.ExportSubjectPublicKeyInfo()))
        {
            throw new ArgumentException("The CA key does not match the CA certificate.", nameof(caKey));
        }

        if (caPublicKey.AsSpan().SequenceEqual(leafKey.ExportSubjectPublicKeyInfo()))
        {
            throw new ArgumentException("The leaf key must be a separate key pair from the CA key.", nameof(leafKey));
        }

        // A leaf may not outlive its CA: in the CA's final LeafLifetime the leaf's notAfter is clamped to the CA's.
        DateTimeOffset issuedAt = WholeSeconds(now);
        DateTimeOffset notBefore = issuedAt - Backdate;
        DateTimeOffset caNotAfter = new(caCertificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        if (caNotAfter <= issuedAt)
        {
            throw new ArgumentException("The CA certificate has expired; reset the identity to issue a new CA.", nameof(caCertificate));
        }

        DateTimeOffset notAfter = notBefore + LeafLifetime;
        if (notAfter > caNotAfter)
        {
            notAfter = caNotAfter;
        }

        SubjectAlternativeNameBuilder subjectAlternativeName = new();
        subjectAlternativeName.AddDnsName(DeviceName.ToMdnsName(name));

        CertificateRequest request = new(subject, leafKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid)], critical: false));
        request.CertificateExtensions.Add(subjectAlternativeName.Build(critical: false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
            caCertificate, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        // The issuer is the CA certificate's own encoded subject, so chains build by exact name match.
        return request.Create(caCertificate.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey), notBefore, notAfter, NewSerialNumber());
    }

    /// <summary>
    /// The DER value of the critical nameConstraints extension (OID 2.5.29.30) for <paramref name="mdnsName"/>:
    /// permitted dNSName <paramref name="mdnsName"/>; excluded iPAddress <c>0.0.0.0/0</c> (8 zero bytes) and
    /// <c>::/0</c> (32 zero bytes).
    /// </summary>
    /// <param name="mdnsName">The full mDNS name, <c>&lt;name&gt;.local</c>.</param>
    public static byte[] EncodeNameConstraints(string mdnsName)
    {
        ArgumentNullException.ThrowIfNull(mdnsName);
        if (!mdnsName.EndsWith(DeviceName.LocalSuffix, StringComparison.Ordinal)
            || !DeviceName.IsValidLabel(mdnsName[..^DeviceName.LocalSuffix.Length]))
        {
            throw new ArgumentException("The mDNS name must be a valid device name followed by .local.", nameof(mdnsName));
        }

        Asn1Tag permittedSubtrees = new(TagClass.ContextSpecific, 0, isConstructed: true);
        Asn1Tag excludedSubtrees = new(TagClass.ContextSpecific, 1, isConstructed: true);
        Asn1Tag dnsName = new(TagClass.ContextSpecific, 2);
        Asn1Tag ipAddress = new(TagClass.ContextSpecific, 7);

        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(permittedSubtrees))
            {
                using (writer.PushSequence())
                {
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, mdnsName, dnsName);
                }
            }

            using (writer.PushSequence(excludedSubtrees))
            {
                using (writer.PushSequence())
                {
                    // 0.0.0.0 with mask 0.0.0.0: every IPv4 address.
                    writer.WriteOctetString(new byte[8], ipAddress);
                }

                using (writer.PushSequence())
                {
                    // :: with mask ::, every IPv6 address.
                    writer.WriteOctetString(new byte[32], ipAddress);
                }
            }
        }

        return writer.Encode();
    }

    private static DateTimeOffset WholeSeconds(DateTimeOffset time) =>
        new(time.UtcTicks - (time.UtcTicks % TimeSpan.TicksPerSecond), TimeSpan.Zero);

    private static byte[] NewSerialNumber()
    {
        byte[] serial = RandomNumberGenerator.GetBytes(SerialNumberLength);
        // Clear the sign bit so the serial is positive, and set the next bit so the leading byte is never zero:
        // the DER INTEGER keeps all 16 bytes (126 random bits) and needs no padding byte.
        serial[0] = (byte)((serial[0] & 0x7F) | 0x40);
        return serial;
    }

    private static void ThrowIfNotP256(ECDsa key, [CallerArgumentExpression(nameof(key))] string? paramName = null)
    {
        PublicKey publicKey = new(key);
        if (publicKey.Oid.Value != EcPublicKeyOid || publicKey.EncodedParameters?.RawData is not { } parameters
            || !parameters.AsSpan().SequenceEqual(s_p256CurveParameters.AsSpan()))
        {
            throw new ArgumentException("The key must be an ECDSA key on curve P-256.", paramName);
        }
    }
}
