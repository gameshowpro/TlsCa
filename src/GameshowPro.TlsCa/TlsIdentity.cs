namespace GameshowPro.TlsCa;

/// <summary>
/// An immutable snapshot of a device's public identity: its name, the CA and leaf certificates (DER) and the facts
/// derived from them. It holds no private key and no disposable object, so it can be shared freely across threads.
/// </summary>
public sealed class TlsIdentity
{
    /// <summary>Creates a snapshot from the device name and the DER encodings of its certificates.</summary>
    /// <exception cref="ArgumentException">The name is not a valid device name.</exception>
    /// <exception cref="CryptographicException">A certificate cannot be decoded.</exception>
    public TlsIdentity(string name, ImmutableArray<byte> caCertificateDer, ImmutableArray<byte> leafCertificateDer, string? previousCaFingerprintSha256)
    {
        MdnsName = DeviceName.ToMdnsName(name);
        Name = name;
        if (caCertificateDer.IsDefaultOrEmpty || leafCertificateDer.IsDefaultOrEmpty)
        {
            throw new ArgumentException("Both certificates are required.");
        }

        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(caCertificateDer.AsSpan());
        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(leafCertificateDer.AsSpan());
        CaCertificateDer = caCertificateDer;
        LeafCertificateDer = leafCertificateDer;
        CaFingerprintSha256 = Fingerprint.Sha256(ca);
        LeafFingerprintSha256 = Fingerprint.Sha256(leaf);
        CaNotBefore = Utc(ca.NotBefore);
        CaNotAfter = Utc(ca.NotAfter);
        LeafNotBefore = Utc(leaf.NotBefore);
        LeafNotAfter = Utc(leaf.NotAfter);
        PreviousCaFingerprintSha256 = previousCaFingerprintSha256;

        static DateTimeOffset Utc(DateTime local) => new(local.ToUniversalTime(), TimeSpan.Zero);
    }

    /// <summary>The device name, a single DNS label such as <c>studio-pc-triggergate</c>.</summary>
    public string Name { get; }

    /// <summary>The full mDNS name, <c>&lt;name&gt;.local</c>.</summary>
    public string MdnsName { get; }

    /// <summary>The device CA certificate, DER. This is what clients install.</summary>
    public ImmutableArray<byte> CaCertificateDer { get; }

    /// <summary>The CA certificate's SHA-256 fingerprint, <c>AB:CD:...</c>.</summary>
    public string CaFingerprintSha256 { get; }

    /// <summary>The CA certificate's notBefore (UTC).</summary>
    public DateTimeOffset CaNotBefore { get; }

    /// <summary>The CA certificate's notAfter (UTC). No leaf is valid beyond this; a reset is needed before it.</summary>
    public DateTimeOffset CaNotAfter { get; }

    /// <summary>The leaf certificate served over HTTPS, DER.</summary>
    public ImmutableArray<byte> LeafCertificateDer { get; }

    /// <summary>The leaf certificate's SHA-256 fingerprint.</summary>
    public string LeafFingerprintSha256 { get; }

    /// <summary>The leaf certificate's notBefore (UTC).</summary>
    public DateTimeOffset LeafNotBefore { get; }

    /// <summary>The leaf certificate's notAfter (UTC).</summary>
    public DateTimeOffset LeafNotAfter { get; }

    /// <summary>The fingerprint of the CA this identity replaced in its most recent reset, or null.</summary>
    public string? PreviousCaFingerprintSha256 { get; }

    public override string ToString() => $"{MdnsName} (CA {CaFingerprintSha256})";
}
