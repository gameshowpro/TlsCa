namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// How HTTPS is provided, decided once by <c>AddGameshowProTlsCa</c> from the options and the app configuration, in this
/// order: <see cref="Off"/>, <see cref="OwnCertificate"/>, <see cref="KestrelCertificate"/>, <see cref="BuiltInCa"/>.
/// </summary>
public enum TlsCaMode
{
    /// <summary>
    /// The per-installation CA: the identity is loaded or created, its leaf is served on
    /// <see cref="TlsCaOptions.HttpsPort"/>, renewed and advertised over mDNS, and the management page offers the CA.
    /// </summary>
    BuiltInCa,

    /// <summary>
    /// The library serves the certificate at <see cref="TlsCaOptions.CertificatePath"/> on
    /// <see cref="TlsCaOptions.HttpsPort"/>, and reloads it when the file changes. No CA is created or loaded.
    /// </summary>
    OwnCertificate,

    /// <summary>
    /// Kestrel is configured with a certificate (an <c>https</c> <c>Kestrel:Endpoints</c> URL or
    /// <c>Kestrel:Certificates:Default:Path</c>) and serves HTTPS itself. The library adds no listener.
    /// </summary>
    KestrelCertificate,

    /// <summary>HTTPS is off: the effective <see cref="TlsCaOptions.HttpsPort"/> is <c>0</c>.</summary>
    Off,
}
