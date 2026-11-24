namespace GameshowPro.TlsCa;

/// <summary>
/// The single seam for leaf issuance (Part 1, "Keep one seam for the future"). The local implementation signs with
/// the stored device CA key for the stored device name; a future site-wide CA can replace only this, without touching
/// the servers. Implementations take the name from their own stored state, never from a caller or a request.
/// </summary>
public interface ILeafIssuer
{
    /// <summary>
    /// Generates a new leaf key and issues a leaf certificate for it, using <paramref name="now"/> as the issuance time.
    /// The caller owns the result and disposes it. Asynchronous so that a future site-wide CA can issue remotely.
    /// </summary>
    ValueTask<IssuedLeaf> Issue(DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>
/// A newly issued leaf: its private key and its certificate. <see cref="Certificate"/> carries no private key;
/// combine the two only where the TLS server needs them. Disposing the instance disposes both.
/// </summary>
public sealed class IssuedLeaf(ECDsa key, X509Certificate2 certificate) : IDisposable
{
    /// <summary>The leaf private key (ECDSA P-256).</summary>
    public ECDsa Key { get; } = key ?? throw new ArgumentNullException(nameof(key));

    /// <summary>The leaf certificate, without its private key.</summary>
    public X509Certificate2 Certificate { get; } = certificate ?? throw new ArgumentNullException(nameof(certificate));

    public void Dispose()
    {
        Key.Dispose();
        Certificate.Dispose();
    }
}
