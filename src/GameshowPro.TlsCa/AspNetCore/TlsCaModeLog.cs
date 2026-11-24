namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// Logs once, at startup, how HTTPS is provided when the built-in CA is not used: Kestrel's own certificate, HTTPS off,
/// or a warning when both the library's certificate settings and Kestrel configure a certificate. (The own certificate's
/// details are logged by <see cref="OwnCertificateSource"/> when it loads.)
/// </summary>
internal sealed partial class TlsCaModeLog(TlsCaModeResolution resolution, TlsCaOptions options, ILogger<TlsCaModeLog> logger) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        switch (resolution.Mode)
        {
            case TlsCaMode.KestrelCertificate:
                LogKestrelCertificate(resolution.KestrelSetting ?? "Kestrel");
                break;

            case TlsCaMode.Off:
                LogOff();
                break;

            case TlsCaMode.OwnCertificate when resolution.KestrelSetting is { } kestrelSetting:
                string key = string.IsNullOrWhiteSpace(options.ConfigurationSection)
                    ? $"{nameof(TlsCaOptions)}.{nameof(TlsCaOptions.CertificatePath)}"
                    : $"{options.ConfigurationSection.Trim()}:{TlsCaConfiguration.CertificatePathKey}";
                LogBothConfigured(key, options.CertificatePath ?? "", kestrelSetting, options.HttpsPort);
                break;

            case TlsCaMode.OwnCertificate:
            case TlsCaMode.BuiltInCa:
            default:
                break;
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(EventId = 30, Level = LogLevel.Information, Message = "HTTPS uses the certificate Kestrel is configured with ({KestrelSetting}); GameshowPro.TlsCa adds no HTTPS listener and does not use its built-in CA.")]
    private partial void LogKestrelCertificate(string kestrelSetting);

    [LoggerMessage(EventId = 31, Level = LogLevel.Information, Message = "HTTPS is off (the HTTPS port is 0); the built-in CA is not used.")]
    private partial void LogOff();

    [LoggerMessage(EventId = 32, Level = LogLevel.Warning, Message = "Both {CertificatePathKey} ({CertificatePath}) and {KestrelSetting} configure a certificate. GameshowPro.TlsCa serves that file on port {HttpsPort}; Kestrel serves its own configuration separately.")]
    private partial void LogBothConfigured(string certificatePathKey, string certificatePath, string kestrelSetting, int httpsPort);
}
