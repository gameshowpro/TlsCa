namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>Reads the app configuration that decides how HTTPS is provided (<see cref="TlsCaMode"/>).</summary>
public static class TlsCaConfiguration
{
    /// <summary>The key, under <see cref="TlsCaOptions.ConfigurationSection"/>, of the HTTPS port.</summary>
    public const string HttpsPortKey = "HttpsPort";

    /// <summary>The key, under <see cref="TlsCaOptions.ConfigurationSection"/>, of the storage directory.</summary>
    public const string StorageDirectoryKey = "TlsStorageDirectory";

    /// <summary>The key, under <see cref="TlsCaOptions.ConfigurationSection"/>, of <see cref="TlsCaOptions.CertificatePath"/>.</summary>
    public const string CertificatePathKey = "CertificatePath";

    /// <summary>The key, under <see cref="TlsCaOptions.ConfigurationSection"/>, of <see cref="TlsCaOptions.CertificateKeyPath"/>.</summary>
    public const string CertificateKeyPathKey = "CertificateKeyPath";

    /// <summary>The key, under <see cref="TlsCaOptions.ConfigurationSection"/>, of <see cref="TlsCaOptions.CertificatePassword"/>.</summary>
    public const string CertificatePasswordKey = "CertificatePassword";

    private const string DefaultCertificatePathKey = "Kestrel:Certificates:Default:Path";

    /// <summary>
    /// Whether Kestrel is configured with a certificate of its own (<see cref="TlsCaMode.KestrelCertificate"/>, unless
    /// HTTPS is off or <see cref="TlsCaOptions.CertificatePath"/> is set): a default certificate is configured
    /// (<c>Kestrel:Certificates:Default:Path</c> is not blank), or any configured endpoint
    /// (<c>Kestrel:Endpoints:&lt;name&gt;:Url</c>) is an <c>https</c> URL. Plain-HTTP configured endpoints do not count:
    /// Kestrel binds them and the library adds its HTTPS listener next to them.
    /// </summary>
    public static bool HasExternalCertificate(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return KestrelCertificate(configuration).Setting is not null;
    }

    /// <summary>
    /// The Kestrel setting that configures a certificate (the first <c>https</c> endpoint's URL key, else the default
    /// certificate key), or null; and the port of that <c>https</c> endpoint, or <c>0</c> when there is none or it cannot
    /// be read.
    /// </summary>
    internal static (string? Setting, int Port) KestrelCertificate(IConfiguration configuration)
    {
        foreach (IConfigurationSection endpoint in configuration.GetSection("Kestrel:Endpoints").GetChildren())
        {
            string? url = endpoint["Url"]?.Trim();
            if (url?.StartsWith("https:", StringComparison.OrdinalIgnoreCase) == true)
            {
                return ($"Kestrel:Endpoints:{endpoint.Key}:Url", PortOf(url));
            }
        }

        return string.IsNullOrWhiteSpace(configuration[DefaultCertificatePathKey]) ? (null, 0) : (DefaultCertificatePathKey, 0);

        static int PortOf(string url)
        {
            // Kestrel's wildcard hosts are not valid in a Uri.
            string parsable = url.Replace("://*", "://0.0.0.0", StringComparison.Ordinal).Replace("://+", "://0.0.0.0", StringComparison.Ordinal);
            return Uri.TryCreate(parsable, UriKind.Absolute, out Uri? uri) && uri.Port is > 0 and <= 65535 ? uri.Port : 0;
        }
    }

    /// <summary>
    /// Applies <c>&lt;section&gt;:HttpsPort</c>, <c>TlsStorageDirectory</c>, <c>CertificatePath</c>,
    /// <c>CertificateKeyPath</c> and <c>CertificatePassword</c> to <paramref name="options"/> when
    /// <see cref="TlsCaOptions.ConfigurationSection"/> is set. Blank values are ignored.
    /// </summary>
    /// <exception cref="InvalidOperationException">The configured port is not a number, or is outside 0 to 65535.</exception>
    internal static void Apply(TlsCaOptions options, IConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(options.ConfigurationSection))
        {
            return;
        }

        string section = options.ConfigurationSection.Trim();
        string portKey = $"{section}:{HttpsPortKey}";
        string? configured = configuration[portKey];
        if (!string.IsNullOrWhiteSpace(configured))
        {
            if (!int.TryParse(configured, NumberStyles.Integer, CultureInfo.InvariantCulture, out int port))
            {
                throw new InvalidOperationException($"{portKey} must be a number (was '{configured}').");
            }

            if (port is < 0 or > 65535)
            {
                throw new InvalidOperationException($"{portKey} must be between 1 and 65535, or 0 to turn HTTPS off (was {port}).");
            }

            options.HttpsPort = port;
        }

        options.StorageDirectory = Read(StorageDirectoryKey) ?? options.StorageDirectory;
        options.CertificatePath = Read(CertificatePathKey) ?? options.CertificatePath;
        options.CertificateKeyPath = Read(CertificateKeyPathKey) ?? options.CertificateKeyPath;
        options.CertificatePassword = Read(CertificatePasswordKey) ?? options.CertificatePassword;

        string? Read(string key) => configuration[$"{section}:{key}"] is { } value && !string.IsNullOrWhiteSpace(value) ? value : null;
    }

    /// <summary>
    /// Decides the mode from the effective options (after <see cref="Apply"/>) and the Kestrel configuration: HTTPS port
    /// <c>0</c> is <see cref="TlsCaMode.Off"/>; else <see cref="TlsCaOptions.CertificatePath"/> is
    /// <see cref="TlsCaMode.OwnCertificate"/>; else a Kestrel certificate is <see cref="TlsCaMode.KestrelCertificate"/>;
    /// else <see cref="TlsCaMode.BuiltInCa"/>.
    /// </summary>
    internal static TlsCaModeResolution Resolve(TlsCaOptions options, IConfiguration configuration)
    {
        (string? kestrelSetting, int kestrelPort) = KestrelCertificate(configuration);
        TlsCaMode mode = options.HttpsPort == 0
            ? TlsCaMode.Off
            : !string.IsNullOrWhiteSpace(options.CertificatePath)
                ? TlsCaMode.OwnCertificate
                : kestrelSetting is not null ? TlsCaMode.KestrelCertificate : TlsCaMode.BuiltInCa;
        return new(mode, kestrelSetting, kestrelPort);
    }

    /// <summary>
    /// The version reported when <see cref="TlsCaOptions.Version"/> is null: <paramref name="assembly"/>'s informational
    /// version up to any <c>+metadata</c> suffix, else its assembly version, else null.
    /// </summary>
    internal static string? DefaultVersion(Assembly? assembly)
    {
        if (assembly is null)
        {
            return null;
        }

        string? informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            int plus = informational.IndexOf('+', StringComparison.Ordinal);
            return plus >= 0 ? informational[..plus] : informational;
        }

        return assembly.GetName().Version?.ToString();
    }
}

/// <summary>The decided mode, and what was found in the Kestrel configuration (for the log and the reported port).</summary>
/// <param name="Mode">The mode.</param>
/// <param name="KestrelSetting">The Kestrel key that configures a certificate, or null.</param>
/// <param name="KestrelHttpsPort">The port of Kestrel's <c>https</c> endpoint, or <c>0</c>.</param>
internal sealed record TlsCaModeResolution(TlsCaMode Mode, string? KestrelSetting, int KestrelHttpsPort);
