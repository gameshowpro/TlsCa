namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>Adds the per-installation TLS CA to an ASP.NET Core app.</summary>
public static partial class TlsCaBuilderExtensions
{
    /// <summary>
    /// Decides how HTTPS is provided (<see cref="TlsCaMode"/>) and sets it up. Call it unconditionally, together with
    /// <see cref="TlsCaApplicationBuilderExtensions.UseGameshowProTlsCa"/> (or
    /// <see cref="TlsCaEndpointExtensions.MapGameshowProTlsCa"/>) on the built app; the app makes the same two calls in
    /// every mode.
    /// </summary>
    /// <returns>The mode. The options instance <paramref name="configure"/> was given holds the effective values.</returns>
    /// <remarks>
    /// <para>
    /// <paramref name="configure"/> is called once, first, on the options instance the library then keeps. When
    /// <see cref="TlsCaOptions.ConfigurationSection"/> is set, its <c>HttpsPort</c>, <c>TlsStorageDirectory</c>,
    /// <c>CertificatePath</c>, <c>CertificateKeyPath</c> and <c>CertificatePassword</c> keys then override the options
    /// (see <see cref="TlsCaConfiguration"/>). Relative certificate paths become absolute against the content root. A
    /// null <see cref="TlsCaOptions.Version"/> becomes the entry assembly's informational version without its
    /// <c>+metadata</c> suffix.
    /// </para>
    /// <para>
    /// The mode, in order of precedence: HTTPS port <c>0</c> is <see cref="TlsCaMode.Off"/>;
    /// <see cref="TlsCaOptions.CertificatePath"/> is <see cref="TlsCaMode.OwnCertificate"/> (when Kestrel also configures
    /// a certificate, a warning names both and each is served as configured); a Kestrel certificate
    /// (<see cref="TlsCaConfiguration.HasExternalCertificate"/>) is <see cref="TlsCaMode.KestrelCertificate"/>; otherwise
    /// <see cref="TlsCaMode.BuiltInCa"/>. <see cref="ITlsCaStatus"/>, the endpoints and the management prefix are
    /// registered in every mode.
    /// </para>
    /// <para>
    /// <see cref="TlsCaMode.BuiltInCa"/>: registers the identity manager (a DI singleton, disposed at shutdown), loads or
    /// creates the identity before Kestrel binds, adds an HTTPS listener on <see cref="TlsCaOptions.HttpsPort"/> on all
    /// interfaces (TLS 1.2 and 1.3, serving the current leaf, so a renewed leaf is used without a restart), and registers
    /// the daily renewal and the mDNS advertisement as hosted services.
    /// </para>
    /// <para>
    /// <see cref="TlsCaMode.OwnCertificate"/>: loads the certificate before Kestrel binds and serves it, with the
    /// intermediates in the file (not on Windows; see the readme), on <see cref="TlsCaOptions.HttpsPort"/> on all
    /// interfaces (TLS 1.2 and 1.3). The files are checked for a change every two seconds and loaded again without a
    /// restart. A certificate that cannot be loaded is logged as an error and leaves the listener bound with failing
    /// handshakes (<see cref="ITlsCaStatus.Problem"/>); the built-in CA is never used instead. Expiry within 30 days is
    /// logged as a warning, daily. No CA is created or loaded, the storage directory is not touched, and there is no
    /// renewal, mDNS advertisement or HTTP root redirect.
    /// </para>
    /// <para>
    /// <see cref="TlsCaMode.KestrelCertificate"/>: adds no listener (Kestrel serves its configured certificate) and logs
    /// one line saying so. <see cref="TlsCaMode.Off"/>: adds no HTTPS listener. In both, as in
    /// <see cref="TlsCaMode.OwnCertificate"/>, there is no CA, renewal, mDNS advertisement or HTTP root redirect.
    /// </para>
    /// <para>
    /// The app keeps declaring its plain-HTTP endpoints the way it does today (<c>UseUrls</c>, <c>ASPNETCORE_URLS</c>,
    /// <c>http_ports</c>, or <c>Kestrel:Endpoints</c>). Kestrel treats code-defined listeners (<c>Listen*</c>) and the
    /// hosting URLs as alternatives and silently drops the URLs when both exist, so this method re-applies the
    /// <c>http://</c> hosting URLs as listeners next to the HTTPS one, using the same host mapping Kestrel uses. When
    /// the app declared no URLs and no <c>Kestrel:Endpoints</c>, <see cref="TlsCaOptions.HttpPort"/> is bound on all
    /// interfaces. Kestrel logs a harmless warning that it is overriding the hosting URLs with the endpoints; the HTTP
    /// URLs are in fact bound. Configured <c>Kestrel:Endpoints</c> are left to Kestrel, which binds them next to the
    /// HTTPS listener. <c>https://</c> hosting URLs are not re-applied. The same applies in <see cref="TlsCaMode.Off"/>
    /// and <see cref="TlsCaMode.OwnCertificate"/>; in <see cref="TlsCaMode.KestrelCertificate"/> nothing is added.
    /// </para>
    /// <para>
    /// With <see cref="TlsCaOptions.AppOwnsListeners"/> true, no mode adds HTTP or HTTPS listeners. The application
    /// configures its own Kestrel endpoints and uses <see cref="ITlsCaHttps"/> in one
    /// <c>ConfigureHttpsDefaults</c> action when <see cref="ITlsCaHttps.SuppliesCertificate"/> is true. The certificate
    /// is chosen for each handshake, including endpoints added by a configuration reload. Set up generated HTTPS
    /// endpoint configuration after this call, or give Kestrel a dedicated configuration source: HTTPS endpoints already
    /// present in the app configuration at this call count as an external Kestrel certificate for mode resolution.
    /// <see cref="TlsCaOptions.HttpPort"/> and <see cref="TlsCaOptions.HttpsPort"/> still supply the advertised ports.
    /// </para>
    /// <para>
    /// A stored identity that cannot be used, or a first identity that cannot be created (an
    /// <see cref="IdentityStoreException"/>), does not stop the app: it is logged as an error and the app starts without an
    /// identity. The HTTPS listener is still bound but its handshakes fail, the certificate endpoints answer 503, the
    /// management page is served, <see cref="ITlsCaStatus.IdentityProblem"/> holds the reason, and a gated reset installs
    /// a new identity without a restart.
    /// </para>
    /// <para>
    /// The storage directory defaults to <c>%ProgramData%\GameshowPro\&lt;Product&gt;\tls</c> on Windows and
    /// <c>/var/lib/gameshowpro/&lt;applabel&gt;/tls</c> elsewhere.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">A configured port is not a number or is out of range.</exception>
    /// <exception cref="ArgumentException">The options are invalid.</exception>
    public static TlsCaMode AddGameshowProTlsCa(this WebApplicationBuilder builder, Action<TlsCaOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);
        TlsCaOptions options = new();
        configure(options);
        TlsCaConfiguration.Apply(options, builder.Configuration);
        Validate(options);
        options.CertificatePath = FullPath(options.CertificatePath, builder.Environment.ContentRootPath);
        options.CertificateKeyPath = FullPath(options.CertificateKeyPath, builder.Environment.ContentRootPath);
        TlsCaModeResolution resolution = TlsCaConfiguration.Resolve(options, builder.Configuration);
        AddCore(builder, options, resolution);
        return resolution.Mode;
        static void AddCore(WebApplicationBuilder builder, TlsCaOptions options, TlsCaModeResolution resolution)
        {
            TlsCaMode mode = resolution.Mode;
            options.Version ??= TlsCaConfiguration.DefaultVersion(Assembly.GetEntryAssembly());
            ITlsCaGate gate = options.Gate ?? new LoopbackGate();
            IServiceCollection services = builder.Services;
            services.TryAddSingleton(TimeProvider.System);
            _ = services.AddSingleton(options);
            _ = services.AddSingleton(gate);
            _ = services.AddSingleton(resolution);
            _ = services.AddSingleton<ITlsCaHttps, TlsCaHttps>();
            _ = services.AddSingleton(provider => new TlsCaStatus(
                resolution,
                options,
                mode == TlsCaMode.BuiltInCa ? provider.GetRequiredService<TlsIdentityManager>() : null,
                mode == TlsCaMode.OwnCertificate ? provider.GetRequiredService<OwnCertificateSource>() : null,
                provider.GetRequiredService<ILogger<TlsCaStatus>>()));
            _ = services.AddSingleton<ITlsCaStatus>(static provider => provider.GetRequiredService<TlsCaStatus>());
            _ = services.AddSingleton<TlsCaMarker>();
            switch (mode)
            {
                case TlsCaMode.BuiltInCa:
                    if (string.IsNullOrWhiteSpace(options.StorageDirectory))
                    {
                        options.StorageDirectory = DefaultStorageDirectory(options);
                    }

                    // A factory registration is disposed by the container at shutdown. The identity is loaded here, on first
                    // use, which is before Kestrel binds because KestrelTlsConfigurator resolves it while configuring the server.
                    _ = services.AddSingleton(CreateManager);
                    _ = services.AddSingleton<IConfigureOptions<KestrelServerOptions>, KestrelTlsConfigurator>();
                    _ = services.AddHostedService<TlsCaRenewalService>();
                    if (options.AdvertiseMdns)
                    {
                        _ = services.AddSingleton<TlsCaMdnsService>();
                        _ = services.AddSingleton<ITlsCaMdns>(static provider => provider.GetRequiredService<TlsCaMdnsService>());
                        _ = services.AddSingleton<IHostedService>(static provider => provider.GetRequiredService<TlsCaMdnsService>());
                    }

                    break;

                case TlsCaMode.OwnCertificate:
                    // Loaded on first use, which is before Kestrel binds (KestrelTlsConfigurator resolves it); disposed at shutdown.
                    _ = services.AddSingleton(static provider => new OwnCertificateSource(
                        provider.GetRequiredService<TlsCaOptions>(),
                        provider.GetRequiredService<TimeProvider>(),
                        provider.GetRequiredService<ILogger<OwnCertificateSource>>()));
                    _ = services.AddSingleton<IConfigureOptions<KestrelServerOptions>, KestrelTlsConfigurator>();
                    _ = services.AddHostedService<OwnCertificateMonitor>();
                    _ = services.AddHostedService<TlsCaModeLog>();
                    break;

                case TlsCaMode.Off:
                    _ = services.AddSingleton<IConfigureOptions<KestrelServerOptions>, KestrelTlsConfigurator>();
                    _ = services.AddHostedService<TlsCaModeLog>();
                    break;

                case TlsCaMode.KestrelCertificate:
                default:
                    _ = services.AddHostedService<TlsCaModeLog>();
                    break;
            }

            if (mode != TlsCaMode.BuiltInCa || !options.AdvertiseMdns)
            {
                _ = services.AddSingleton<ITlsCaMdns>(new InactiveTlsCaMdns(options));
            }

            static TlsIdentityManager CreateManager(IServiceProvider provider)
            {
                TlsCaOptions managerOptions = provider.GetRequiredService<TlsCaOptions>();
                FileIdentityStore store = new(managerOptions.StorageDirectory, managerOptions.KeyProtectorOverride ?? FileIdentityStore.DefaultKeyProtector(), provider.GetService<ILogger<FileIdentityStore>>());
                TlsIdentityManager manager = new(managerOptions, store, provider.GetRequiredService<TimeProvider>(), provider.GetService<ILogger<TlsIdentityManager>>());
                try
                {
                    _ = manager.LoadOrCreate().AsTask().GetAwaiter().GetResult();
                    return manager;
                }
                catch (IdentityStoreException)
                {
                    // The manager has logged the reason as an error. The app keeps running without an identity: HTTPS handshakes
                    // fail, the certificate endpoints answer 503, and a gated reset installs a new identity on the running listener.
                    LogRunningWithoutIdentity(provider.GetService<ILogger<TlsCaMarker>>() ?? NullLogger<TlsCaMarker>.Instance, managerOptions.HttpsPort, TlsCaPaths.WellKnownPrefix + "/");
                    return manager;
                }
                catch
                {
                    manager.Dispose();
                    throw;
                }
            }
        }

        static void Validate(TlsCaOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.Product))
            {
                throw new ArgumentException("Set TlsCaOptions.Product.", nameof(options));
            }

            if (options.HttpsPort is < 0 or > 65535)
            {
                throw new ArgumentException("TlsCaOptions.HttpsPort must be between 1 and 65535, or 0 to turn HTTPS off.", nameof(options));
            }

            if (!string.IsNullOrWhiteSpace(options.CertificateKeyPath) && string.IsNullOrWhiteSpace(options.CertificatePath))
            {
                throw new ArgumentException("TlsCaOptions.CertificateKeyPath is set but TlsCaOptions.CertificatePath is not.", nameof(options));
            }

            if (options.HttpPort is < 0 or > 65535)
            {
                throw new ArgumentException("TlsCaOptions.HttpPort must be between 0 and 65535 (0 when the app has no plain-HTTP port to advertise).", nameof(options));
            }
        }

    }

    private static string? FullPath(string? path, string contentRoot) =>
        string.IsNullOrWhiteSpace(path) ? null : Path.GetFullPath(path.Trim(), string.IsNullOrEmpty(contentRoot) ? AppContext.BaseDirectory : contentRoot);


    [LoggerMessage(EventId = 10, Level = LogLevel.Warning, Message = "Running without a TLS identity: HTTPS connections on port {HttpsPort} fail and the CA certificate cannot be downloaded until the identity is reset with Reset on the management page, {Path} (with the default gate, opened on this machine through a localhost address).")]
    private static partial void LogRunningWithoutIdentity(ILogger logger, int httpsPort, string path);


    internal static string DefaultStorageDirectory(TlsCaOptions options)
    {
        if (OperatingSystem.IsWindows())
        {
            string product = SanitizePathPart(string.IsNullOrWhiteSpace(options.Product) ? options.AppLabel : options.Product);
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GameshowPro", product, "tls");
        }

        string label = SanitizePathPart(string.IsNullOrWhiteSpace(options.AppLabel) ? options.ExplicitName ?? options.Product : options.AppLabel).ToLowerInvariant();
        return Path.Combine("/var/lib/gameshowpro", label, "tls");
    }

    private static string SanitizePathPart(string value)
    {
        char[] invalid = Path.GetInvalidFileNameChars();
        string cleaned = new([.. value.Trim().Select(c => Array.IndexOf(invalid, c) >= 0 ? '-' : c)]);
        return cleaned.Length == 0 ? "app" : cleaned;
    }
}
