namespace GameshowPro.TlsCa;

/// <summary>Combines the leaf certificate with its private key in the form the platform's TLS stack can serve.</summary>
internal static class ServerCertificateFactory
{
    /// <summary>
    /// Returns a new certificate holding <paramref name="leaf"/> and <paramref name="leafKey"/>, and nothing else: no CA
    /// or other certificate travels with it, so the TLS stack sends the leaf only. The caller owns the result and must
    /// dispose it (not before every TLS handshake that may still use it has finished).
    /// </summary>
    /// <remarks>See <see cref="ForPlatform"/>.</remarks>
    public static X509Certificate2 Create(X509Certificate2 leaf, ECDsa leafKey) => ForPlatform(leaf.CopyWithPrivateKey(leafKey));

    /// <summary>
    /// Takes ownership of <paramref name="withKey"/> (a certificate with its private key, of any key type) and returns the
    /// certificate the platform's TLS stack can serve: on Windows a new certificate, and <paramref name="withKey"/> is
    /// disposed; elsewhere <paramref name="withKey"/> itself. The result holds that one certificate only.
    /// </summary>
    /// <remarks>
    /// On Windows, SChannel cannot use a private key that exists only in memory, so the pair is re-imported from an
    /// in-memory PKCS#12 into a key container in the current account's profile (CNG, not exportable). Because the
    /// import does not ask to persist the key, the container is deleted when the returned certificate is disposed; a
    /// certificate that is never disposed (for example after a crash) leaves its container behind. Nothing is added to
    /// any certificate store. Elsewhere the key stays in memory.
    /// </remarks>
    public static X509Certificate2 ForPlatform(X509Certificate2 withKey)
    {
        if (!OperatingSystem.IsWindows())
        {
            return withKey;
        }

        using (withKey)
        {
            // The PKCS#12 never leaves this method, so its password only satisfies the format.
            string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            byte[] pkcs12 = withKey.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password);
            try
            {
                return X509CertificateLoader.LoadPkcs12(pkcs12, password, X509KeyStorageFlags.UserKeySet);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs12);
            }
        }
    }
}
