namespace GameshowPro.TlsCa;

/// <summary>Protects private keys (PKCS#8) before they are written to disk, and recovers them when read.</summary>
public interface IKeyProtector
{
    /// <summary>
    /// Identifies the protection scheme. It is recorded next to the protected keys, so a file is never unprotected with
    /// a different scheme from the one that protected it.
    /// </summary>
    string Id { get; }

    /// <summary>Returns the protected form of <paramref name="plaintext"/>.</summary>
    byte[] Protect(byte[] plaintext);

    /// <summary>Recovers the plaintext from <paramref name="protectedData"/>.</summary>
    /// <exception cref="CryptographicException">The data cannot be unprotected here.</exception>
    byte[] Unprotect(byte[] protectedData);
}

/// <summary>
/// Windows DPAPI with machine scope. The ACL on the storage directory limits who can read the protected file; DPAPI
/// keeps the keys unreadable if the file is copied to another machine.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiKeyProtector : IKeyProtector
{
    /// <summary>The <see cref="Id"/> of this scheme.</summary>
    public const string SchemeId = "dpapi-localmachine";

    // Separates these blobs from any other DPAPI machine-scope data.
    private static readonly byte[] s_entropy = "GameshowPro.TlsCa private key"u8.ToArray();

    /// <inheritdoc/>
    public string Id => SchemeId;

    /// <inheritdoc/>
    public byte[] Protect(byte[] plaintext) => ProtectedData.Protect(plaintext, s_entropy, DataProtectionScope.LocalMachine);

    /// <inheritdoc/>
    public byte[] Unprotect(byte[] protectedData) => ProtectedData.Unprotect(protectedData, s_entropy, DataProtectionScope.LocalMachine);
}

/// <summary>
/// No encryption at rest, for Linux, where the keys are protected by file permissions only (directory 0700, file 0600).
/// An accepted residual risk, equivalent to an ESP32 without flash encryption.
/// </summary>
public sealed class PassthroughKeyProtector : IKeyProtector
{
    /// <summary>The <see cref="Id"/> of this scheme.</summary>
    public const string SchemeId = "none";

    /// <inheritdoc/>
    public string Id => SchemeId;

    /// <inheritdoc/>
    public byte[] Protect(byte[] plaintext) => [.. plaintext];

    /// <inheritdoc/>
    public byte[] Unprotect(byte[] protectedData) => [.. protectedData];
}
