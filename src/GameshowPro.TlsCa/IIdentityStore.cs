namespace GameshowPro.TlsCa;

/// <summary>Persists one device identity.</summary>
public interface IIdentityStore
{
    /// <summary>
    /// Loads the stored identity, or returns null when none has been stored yet. The caller owns and disposes the result.
    /// </summary>
    /// <exception cref="IdentityStoreException">
    /// An identity exists but cannot be read, decoded or decrypted. This is never treated as "no identity", because
    /// silently creating a new identity would break every client's trust.
    /// </exception>
    StoredIdentity? Load();

    /// <summary>
    /// Stores <paramref name="identity"/>, replacing any previous identity atomically: after a crash the store holds
    /// either the previous identity or the new one, never a mixture. The caller keeps ownership of <paramref name="identity"/>.
    /// </summary>
    /// <exception cref="IdentityStoreException">The identity could not be written.</exception>
    void Save(StoredIdentity identity);
}
