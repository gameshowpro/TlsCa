namespace GameshowPro.TlsCa;

/// <summary>
/// Everything that makes up a device identity, as passed to and from an <see cref="IIdentityStore"/>: the name, both
/// certificates (DER) and both private keys (PKCS#8). The keys are plain in memory; a store protects them before they
/// reach disk. Disposing the instance zeroes the key buffers.
/// </summary>
public sealed class StoredIdentity : IDisposable
{
    /// <summary>The device name the identity was created for.</summary>
    public required string Name { get; init; }

    /// <summary>The device CA certificate, DER.</summary>
    public required byte[] CaCertificateDer { get; init; }

    /// <summary>The device CA private key, PKCS#8. Never logged, returned by an endpoint or written unprotected.</summary>
    public required byte[] CaPrivateKeyPkcs8 { get; init; }

    /// <summary>The leaf certificate, DER.</summary>
    public required byte[] LeafCertificateDer { get; init; }

    /// <summary>The leaf private key, PKCS#8. Never logged, returned by an endpoint or written unprotected.</summary>
    public required byte[] LeafPrivateKeyPkcs8 { get; init; }

    /// <summary>The fingerprint of the CA replaced by the most recent identity reset, or null.</summary>
    public string? PreviousCaFingerprintSha256 { get; init; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(CaPrivateKeyPkcs8);
        CryptographicOperations.ZeroMemory(LeafPrivateKeyPkcs8);
    }

    public override string ToString() => $"Stored identity {Name}";
}
