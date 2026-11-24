namespace GameshowPro.TlsCa;

/// <summary>
/// Issues leaves locally, signing with the stored device CA key. The device name comes from the stored CA certificate
/// itself (its subject), so this issuer can only ever issue a leaf for the name its CA is constrained to; nothing from
/// a caller or a request reaches certificate construction. A future site-wide CA replaces only this class.
/// </summary>
/// <remarks>
/// The issuer does not take ownership of the CA certificate or key; the caller keeps both alive while issuing.
/// </remarks>
public sealed class LocalLeafIssuer : ILeafIssuer
{
    private readonly X509Certificate2 _caCertificate;
    private readonly ECDsa _caKey;

    /// <summary>Creates an issuer for the device the CA certificate belongs to.</summary>
    /// <param name="caCertificate">The stored device CA certificate.</param>
    /// <param name="caKey">The stored device CA private key.</param>
    /// <exception cref="ArgumentException">The certificate is not a GameshowPro device CA certificate.</exception>
    public LocalLeafIssuer(X509Certificate2 caCertificate, ECDsa caKey)
    {
        ArgumentNullException.ThrowIfNull(caCertificate);
        ArgumentNullException.ThrowIfNull(caKey);
        Name = DeviceNameOf(caCertificate);
        _caCertificate = caCertificate;
        _caKey = caKey;
    }

    /// <summary>The device name the CA certificate belongs to, and the only name this issuer issues for.</summary>
    public string Name { get; }

    /// <inheritdoc/>
    public ValueTask<IssuedLeaf> Issue(DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ECDsa leafKey = CertificateProfiles.CreateKey();
        try
        {
            X509Certificate2 certificate = CertificateProfiles.CreateLeaf(Name, _caCertificate, _caKey, leafKey, now);
            return ValueTask.FromResult(new IssuedLeaf(leafKey, certificate));
        }
        catch
        {
            leafKey.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The device name of a device CA certificate, read from its subject
    /// (<c>CN=GameshowPro Device CA &lt;name&gt;, O=GameshowPro</c>).
    /// </summary>
    /// <exception cref="ArgumentException">The certificate subject is not a device CA subject.</exception>
    internal static string DeviceNameOf(X509Certificate2 caCertificate, [CallerArgumentExpression(nameof(caCertificate))] string? paramName = null)
    {
        string commonName = caCertificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        string name = commonName.StartsWith(CertificateProfiles.CaCommonNamePrefix, StringComparison.Ordinal)
            ? commonName[CertificateProfiles.CaCommonNamePrefix.Length..]
            : "";
        if (!DeviceName.IsValidLabel(name)
            || !caCertificate.SubjectName.RawData.AsSpan().SequenceEqual(CertificateProfiles.CaSubject(name).RawData))
        {
            throw new ArgumentException("The certificate is not a GameshowPro device CA certificate.", paramName);
        }

        return name;
    }
}
