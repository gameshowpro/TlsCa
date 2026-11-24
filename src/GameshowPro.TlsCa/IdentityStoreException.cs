namespace GameshowPro.TlsCa;

/// <summary>
/// A stored identity exists but cannot be used (unreadable, corrupt, inconsistent or undecryptable), or an identity
/// could not be written. The message says what is wrong and never contains key material. Recovery is to restore access
/// to the file or to reset the identity explicitly; the library never replaces an unusable identity on its own.
/// </summary>
public sealed class IdentityStoreException : Exception
{
    public IdentityStoreException()
    {
    }

    public IdentityStoreException(string message)
        : base(message)
    {
    }

    public IdentityStoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
