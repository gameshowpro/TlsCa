namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>Supplies the library certificate to HTTPS endpoints configured by the application.</summary>
public interface ITlsCaHttps
{
    /// <summary>True when the built-in CA or own-certificate mode supplies a server certificate.</summary>
    bool SuppliesCertificate { get; }

    /// <summary>
    /// Configures Kestrel's HTTPS defaults for application-owned endpoints. In off and Kestrel-certificate modes this
    /// leaves the supplied options unchanged. Call from one
    /// <c>ConfigureHttpsDefaults</c> action; Kestrel replaces previous defaults actions rather than composing them.
    /// The certificate is selected for each handshake, including endpoints added after a configuration reload.
    /// </summary>
    void Configure(HttpsConnectionAdapterOptions https);
}

internal sealed class TlsCaHttps(IServiceProvider services, TlsCaModeResolution resolution) : ITlsCaHttps
{
    public bool SuppliesCertificate => resolution.Mode is TlsCaMode.BuiltInCa or TlsCaMode.OwnCertificate;

    public void Configure(HttpsConnectionAdapterOptions https)
    {
        ArgumentNullException.ThrowIfNull(https);
        switch (resolution.Mode)
        {
            case TlsCaMode.BuiltInCa:
                TlsIdentityManager manager = services.GetRequiredService<TlsIdentityManager>();
                https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                https.ServerCertificateSelector = (_, _) => manager.CurrentServerCertificateOrDefault;
                break;

            case TlsCaMode.OwnCertificate:
                OwnCertificateSource source = services.GetRequiredService<OwnCertificateSource>();
                https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                // The selector satisfies Kestrel's certificate check. OnAuthenticate replaces it with the context,
                // so the current certificate and its intermediates are chosen together for every handshake.
                https.ServerCertificateSelector = (_, _) => source.Current?.ServerCertificate;
                https.OnAuthenticate = (_, ssl) =>
                {
                    ssl.ServerCertificateSelectionCallback = null;
                    ssl.ServerCertificateContext = source.ServerOptions().ServerCertificateContext;
                };
                break;

            case TlsCaMode.Off:
            case TlsCaMode.KestrelCertificate:
            default:
                break;
        }
    }
}
