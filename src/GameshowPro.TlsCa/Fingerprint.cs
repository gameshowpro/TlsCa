namespace GameshowPro.TlsCa;

/// <summary>Certificate fingerprints in the format shown to users and carried in <c>info.json</c>.</summary>
public static class Fingerprint
{
    /// <summary>
    /// The SHA-256 hash of the certificate's DER encoding as upper-case hex pairs joined by <c>:</c>,
    /// for example <c>AB:CD:...</c> (95 characters).
    /// </summary>
    public static string Sha256(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Sha256(certificate.RawDataMemory.Span);
    }

    /// <summary>The same fingerprint computed from a certificate's DER encoding.</summary>
    public static string Sha256(ReadOnlySpan<byte> certificateDer)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        _ = SHA256.HashData(certificateDer, hash);
        return string.Join(':', Convert.ToHexString(hash).Chunk(2).Select(pair => new string(pair)));
    }
}
