namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// Configures Kestrel: the HTTPS listener (the manager's current leaf in <see cref="TlsCaMode.BuiltInCa"/>, the app's own
/// certificate in <see cref="TlsCaMode.OwnCertificate"/>, none in <see cref="TlsCaMode.Off"/>), plus the app's own
/// plain-HTTP listeners. Not registered in <see cref="TlsCaMode.KestrelCertificate"/>.
/// </summary>
/// <remarks>
/// Kestrel binds either the code-defined listeners (<c>Listen*</c>, <c>Kestrel:Endpoints</c>) or the hosting URLs
/// (<c>UseUrls</c>, <c>ASPNETCORE_URLS</c>); when both exist it keeps the listeners and ignores the URLs. Adding our
/// HTTPS <c>Listen</c> call would therefore silently cancel the app's HTTP URLs, so they are re-applied here as
/// listeners (also in <see cref="TlsCaMode.Off"/>, so <see cref="TlsCaOptions.HttpPort"/> is bound the same way when the
/// app declared none). The certificate source is resolved (and so the identity or certificate loaded) before Kestrel
/// binds. The HTTPS listener is added even when there is no certificate, so a reset or a fixed file brings
/// HTTPS up on it without a restart. When <see cref="TlsCaOptions.AppOwnsListeners"/> is true, this configurator adds
/// no listeners; the application configures Kestrel and can use <see cref="ITlsCaHttps"/> for its HTTPS defaults.
/// </remarks>
internal sealed partial class KestrelTlsConfigurator(IServiceProvider services, TlsCaModeResolution resolution, TlsCaOptions options, IConfiguration configuration, ILogger<KestrelTlsConfigurator> logger) : IConfigureOptions<KestrelServerOptions>
{
    public void Configure(KestrelServerOptions kestrel)
    {
        if (options.AppOwnsListeners)
        {
            return;
        }

        switch (resolution.Mode)
        {
            case TlsCaMode.BuiltInCa:
                ITlsCaHttps httpsProvider = services.GetRequiredService<ITlsCaHttps>();
                AddHttpListeners(kestrel);
                kestrel.ListenAnyIP(
                    options.HttpsPort,
                    listen => listen.UseHttps(httpsProvider.Configure));
                break;

            case TlsCaMode.OwnCertificate:
                OwnCertificateSource source = services.GetRequiredService<OwnCertificateSource>();
                AddHttpListeners(kestrel);
                // The TLS options, with a certificate context that carries the intermediates, are read per handshake, so a
                // reloaded file is served to the next connection without a restart. While no certificate is loaded the
                // callback throws an AuthenticationException, and the handshake fails (Kestrel logs that at Debug).
                kestrel.ListenAnyIP(
                    options.HttpsPort,
                    listen => listen.UseHttps(new TlsHandshakeCallbackOptions
                    {
                        OnConnection = _ => ValueTask.FromResult(source.ServerOptions()),
                    }));
                break;

            case TlsCaMode.Off:
                AddHttpListeners(kestrel);
                break;

            case TlsCaMode.KestrelCertificate:
            default:
                break;
        }
    }

    private void AddHttpListeners(KestrelServerOptions kestrel)
    {
        bool endpointsConfigured = configuration.GetSection("Kestrel:Endpoints").GetChildren().Any();
        bool preferHostingUrls = bool.TryParse(configuration[WebHostDefaults.PreferHostingUrlsKey], out bool prefer) && prefer;
        string? urls = configuration[WebHostDefaults.ServerUrlsKey];
        string? ports = configuration["http_ports"];
        if (endpointsConfigured && !preferHostingUrls)
        {
            // Kestrel would ignore the hosting URLs next to configured endpoints, so do the same.
            return;
        }

        bool any = false;
        foreach (string url in Split(urls))
        {
            any |= AddUrl(kestrel, url);
        }

        foreach (string port in Split(ports))
        {
            any |= AddUrl(kestrel, $"http://*:{port}");
        }

        if (!any && !endpointsConfigured && options.HttpPort > 0)
        {
            LogDefaultHttpPort(options.HttpPort);
            kestrel.ListenAnyIP(options.HttpPort);
        }
    }

    private bool AddUrl(KestrelServerOptions kestrel, string url)
    {
        // Kestrel's wildcard hosts are not valid in a Uri.
        string parsable = url.Replace("://*", "://0.0.0.0", StringComparison.Ordinal).Replace("://+", "://0.0.0.0", StringComparison.Ordinal);
        if (!Uri.TryCreate(parsable, UriKind.Absolute, out Uri? uri))
        {
            LogUrlIgnored(url, "it is not a valid URL");
            return false;
        }

        if (!uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            LogUrlIgnored(url, "only http URLs are re-applied");
            return false;
        }

        int port = uri.Port;
        if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            kestrel.ListenLocalhost(port);
        }
        else if (IPAddress.TryParse(uri.Host.Trim('[', ']'), out IPAddress? address))
        {
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            {
                kestrel.ListenAnyIP(port);
            }
            else
            {
                kestrel.Listen(address, port);
            }
        }
        else
        {
            LogUrlIgnored(url, "its host is neither localhost, an IP address nor a wildcard");
            return false;
        }

        return true;
    }

    private static string[] Split(string? value) =>
        (value ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The hosting URL {Url} was not re-applied as a Kestrel listener because {Reason}.")]
    private partial void LogUrlIgnored(string url, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "The app declared no HTTP URLs; listening for HTTP on all interfaces on port {Port}.")]
    private partial void LogDefaultHttpPort(int port);
}
