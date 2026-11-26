namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// An app's own server certificate, loaded from <see cref="TlsCaOptions.CertificatePath"/> and ready to serve: the leaf
/// with its private key in the form the platform's TLS stack can use, and the TLS certificate context that carries the
/// intermediates sent in the handshake. Immutable; disposed by <see cref="OwnCertificateSource"/>.
/// </summary>
internal sealed class OwnCertificate : IDisposable
{
    private readonly X509Certificate2 _serverCertificate;
    private readonly X509Certificate2Collection _intermediates;

    private OwnCertificate(X509Certificate2 serverCertificate, X509Certificate2Collection intermediates, bool sendIntermediates)
    {
        _serverCertificate = serverCertificate;
        _intermediates = intermediates;
        Subject = serverCertificate.Subject;
        NotAfter = new DateTimeOffset(serverCertificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        DnsNames = DnsNamesOf(serverCertificate);
        IntermediateCount = intermediates.Count;
        // offline: nothing is downloaded (no AIA or OCSP fetch). See SendsIntermediates for Windows.
        Context = SslStreamCertificateContext.Create(serverCertificate, sendIntermediates ? intermediates : null, offline: true);

        static ImmutableArray<string> DnsNamesOf(X509Certificate2 certificate)
        {
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension.Oid?.Value == "2.5.29.17")
                {
                    return [.. new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical).EnumerateDnsNames()];
                }
            }

            return [];
        }

    }

    /// <summary>
    /// Whether the intermediates from the file are given to the TLS stack. Not on Windows: SChannel sends only a chain it
    /// can build from the machine's certificate stores, and .NET makes it buildable by adding the intermediates (and,
    /// when that is not enough, the root) to the Intermediate Certification Authorities store. This library never adds
    /// anything to a certificate store, so on Windows the leaf is served alone.
    /// </summary>
    public static bool SendsIntermediates => !OperatingSystem.IsWindows();

    /// <summary>The TLS certificate context to serve.</summary>
    public SslStreamCertificateContext Context { get; }

    /// <summary>The server leaf used for Kestrel's per-handshake certificate check.</summary>
    public X509Certificate2 ServerCertificate => _serverCertificate;

    /// <summary>The leaf's subject.</summary>
    public string Subject { get; }

    /// <summary>The leaf's notAfter.</summary>
    public DateTimeOffset NotAfter { get; }

    /// <summary>The DNS names in the leaf's subject alternative name extension, in order; empty when it has none.</summary>
    public ImmutableArray<string> DnsNames { get; }

    /// <summary>How many other certificates the file holds besides the leaf.</summary>
    public int IntermediateCount { get; }

    /// <summary>
    /// Loads <paramref name="path"/>: PEM when <paramref name="keyPath"/> is set or the file holds a PEM block, otherwise
    /// PKCS#12. Throws when the file cannot be read or holds no certificate with a usable private key; the exception
    /// message never holds the password or key material.
    /// </summary>
    public static OwnCertificate Load(string path, string? keyPath, string? password)
    {
        byte[] bytes = File.ReadAllBytes(path);
        try
        {
            (X509Certificate2 leaf, X509Certificate2Collection others) = keyPath is not null || IsPem(bytes)
                ? LoadPem(Encoding.UTF8.GetString(bytes), keyPath, password)
                : LoadPkcs12(bytes, password);
            X509Certificate2? server = null;
            try
            {
                server = ServerCertificateFactory.ForPlatform(leaf);
                return new(server, others, SendsIntermediates);
            }
            catch
            {
                server?.Dispose();
                foreach (X509Certificate2 other in others)
                {
                    other.Dispose();
                }

                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
        // The first certificate is the leaf; the private key is in the key file, else in the certificate file.
        static (X509Certificate2 Leaf, X509Certificate2Collection Others) LoadPem(string certificateText, string? keyPath, string? password)
        {
            string keyText = keyPath is null ? certificateText : File.ReadAllText(keyPath);
            X509Certificate2Collection all = [];
            all.ImportFromPem(certificateText);
            if (all.Count == 0)
            {
                throw new InvalidDataException("The certificate file holds no PEM CERTIFICATE block.");
            }

            X509Certificate2 leaf;
            try
            {
                if (keyText.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal))
                {
                    if (string.IsNullOrEmpty(password))
                    {
                        throw new InvalidDataException("The private key is encrypted and no certificate password is configured.");
                    }

                    leaf = X509Certificate2.CreateFromEncryptedPem(certificateText, keyText, password);
                }
                else
                {
                    leaf = X509Certificate2.CreateFromPem(certificateText, keyText);
                }
            }
            catch
            {
                foreach (X509Certificate2 certificate in all)
                {
                    certificate.Dispose();
                }

                throw;
            }

            all[0].Dispose();
            all.RemoveAt(0);
            return (leaf, all);
        }

        // The leaf is the first certificate with a private key; the others travel as intermediates.
        static (X509Certificate2 Leaf, X509Certificate2Collection Others) LoadPkcs12(byte[] bytes, string? password)
        {
            // On Windows the key is re-imported for SChannel by ServerCertificateFactory.ForPlatform, which exports it, so it is
            // loaded exportable and without a key container of its own. Elsewhere keys stay in memory anyway.
            X509KeyStorageFlags flags = OperatingSystem.IsWindows()
                ? X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable
                : X509KeyStorageFlags.DefaultKeySet;
            X509Certificate2Collection all = X509CertificateLoader.LoadPkcs12Collection(bytes, password, flags);
            X509Certificate2? leaf = all.FirstOrDefault(certificate => certificate.HasPrivateKey);
            if (leaf is null)
            {
                foreach (X509Certificate2 certificate in all)
                {
                    certificate.Dispose();
                }

                throw new InvalidDataException("The PKCS#12 file holds no certificate with a private key.");
            }

            all.Remove(leaf);
            return (leaf, all);
        }

        static bool IsPem(byte[] bytes) => Encoding.UTF8.GetString(bytes).Contains("-----BEGIN ", StringComparison.Ordinal);
    }

    public void Dispose()
    {
        _serverCertificate.Dispose();
        foreach (X509Certificate2 intermediate in _intermediates)
        {
            intermediate.Dispose();
        }
    }

}

/// <summary>
/// Holds the app's own certificate for <see cref="TlsCaMode.OwnCertificate"/>: loads it when created (before Kestrel
/// binds), reloads it when <see cref="Poll"/> sees the file change, and warns about its expiry. A certificate that
/// cannot be loaded leaves no certificate in force (handshakes fail); nothing falls back to the built-in CA.
/// </summary>
internal sealed partial class OwnCertificateSource : IDisposable
{
    public static readonly TimeSpan ExpiryWarningWindow = TimeSpan.FromDays(30);
    public static readonly TimeSpan ExpiryWarningRepeat = TimeSpan.FromDays(1);

    private readonly TlsCaOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger _logger;
    private readonly Lock _lock = new();
    private ImmutableList<OwnCertificate> _retired = [];
    private volatile OwnCertificate? _current;
    private volatile string? _problem;
    private FileStamp _loadedStamp;
    private FileStamp? _pendingStamp;
    private DateTimeOffset? _lastExpiryWarning;
    private bool _disposed;

    public OwnCertificateSource(TlsCaOptions options, TimeProvider timeProvider, ILogger<OwnCertificateSource> logger)
    {
        _options = options;
        _timeProvider = timeProvider;
        _logger = logger;
        lock (_lock)
        {
            Load(FileStamp.Read(Path, KeyPath));
        }
    }

    /// <summary>Raised after the certificate in force or <see cref="Problem"/> changed, on the thread that changed it.</summary>
    public event EventHandler? Changed;

    /// <summary>The certificate in force, or null when it could not be loaded.</summary>
    public OwnCertificate? Current => _current;

    /// <summary>Why there is no certificate in force (names the file, never the password), or null.</summary>
    public string? Problem => _problem;

    private string Path => _options.CertificatePath!;

    private string? KeyPath => string.IsNullOrWhiteSpace(_options.CertificateKeyPath) ? null : _options.CertificateKeyPath;

    /// <summary>
    /// The TLS options for one handshake. Throws <see cref="AuthenticationException"/> while no certificate is in force,
    /// which Kestrel reports as a failed handshake at Debug.
    /// </summary>
    public SslServerAuthenticationOptions ServerOptions() =>
        _current is { } current
            ? new()
            {
                ServerCertificateContext = current.Context,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ClientCertificateRequired = false,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }
            : throw new AuthenticationException("No server certificate is loaded; see the application log.");

    /// <summary>
    /// Reloads the certificate when the certificate or key file changed and has stayed unchanged for one more poll (so a
    /// file still being copied is not read half-written).
    /// </summary>
    public void Poll()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            FileStamp stamp = FileStamp.Read(Path, KeyPath);
            if (stamp == _loadedStamp)
            {
                _pendingStamp = null;
                return;
            }

            if (stamp != _pendingStamp)
            {
                _pendingStamp = stamp;
                return;
            }

            _pendingStamp = null;
            LogFileChanged(Path);
            Load(stamp);
        }
    }

    /// <summary>Warns when the certificate has expired or expires within 30 days: at load, then at most once a day.</summary>
    public void CheckExpiry()
    {
        lock (_lock)
        {
            if (_current is not { } current)
            {
                return;
            }

            DateTimeOffset now = _timeProvider.GetUtcNow();
            if (_lastExpiryWarning is { } last && now - last < ExpiryWarningRepeat)
            {
                return;
            }

            if (current.NotAfter <= now)
            {
                LogExpired(Path, current.NotAfter);
                _lastExpiryWarning = now;
            }
            else if (current.NotAfter - now <= ExpiryWarningWindow)
            {
                LogExpiresSoon(Path, current.NotAfter, (int)Math.Ceiling((current.NotAfter - now).TotalDays));
                _lastExpiryWarning = now;
            }
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _current?.Dispose();
            _current = null;
            foreach (OwnCertificate retired in _retired)
            {
                retired.Dispose();
            }

            _retired = [];
        }
    }

    private void Load(FileStamp stamp)
    {
        _loadedStamp = stamp;
        OwnCertificate? loaded = null;
        string? problem = null;
        try
        {
            loaded = OwnCertificate.Load(Path, KeyPath, _options.CertificatePassword);
        }
#pragma warning disable CA1031 // Any failure to load leaves the listener bound without a certificate; the detail goes to the log.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            problem = $"The certificate {Path} could not be loaded: {exception.Message}";
            LogLoadFailed(Path, exception);
        }

        // A replaced certificate may still be in use by a handshake that selected it, so it is disposed at shutdown.
        if (_current is { } previous)
        {
            _retired = _retired.Add(previous);
        }

        _current = loaded;
        _problem = problem;
        if (loaded is not null)
        {
            LogLoaded(_options.HttpsPort, Path, loaded.Subject, loaded.DnsNames.IsEmpty ? "(none)" : string.Join(", ", loaded.DnsNames), loaded.NotAfter);
            if (loaded.IntermediateCount > 0 && !OwnCertificate.SendsIntermediates)
            {
                LogIntermediatesNotSent(Path, loaded.IntermediateCount);
            }

            _lastExpiryWarning = null;
            CheckExpiry();
        }

        RaiseChanged();

        void RaiseChanged()
        {
            if (Changed is not { } handlers)
            {
                return;
            }

            foreach (EventHandler handler in handlers.GetInvocationList().Cast<EventHandler>())
            {
                try
                {
                    handler(this, EventArgs.Empty);
                }
#pragma warning disable CA1031 // A status handler must not break certificate loading.
                catch (Exception exception)
#pragma warning restore CA1031
                {
                    LogHandlerFailed(exception);
                }
            }
        }
    }

    [LoggerMessage(EventId = 20, Level = LogLevel.Information, Message = "HTTPS on port {HttpsPort} serves the certificate {Path}: subject {Subject}, DNS names {DnsNames}, expires {NotAfter:u}. The built-in CA is not used.")]
    private partial void LogLoaded(int httpsPort, string path, string subject, string dnsNames, DateTimeOffset notAfter);

    [LoggerMessage(EventId = 21, Level = LogLevel.Error, Message = "The certificate {Path} could not be loaded. HTTPS handshakes fail until the file is fixed; it is loaded again when it changes. The built-in CA is not used.")]
    private partial void LogLoadFailed(string path, Exception exception);

    [LoggerMessage(EventId = 22, Level = LogLevel.Information, Message = "The certificate file {Path} (or its key file) changed; loading it again.")]
    private partial void LogFileChanged(string path);

    [LoggerMessage(EventId = 23, Level = LogLevel.Warning, Message = "The certificate {Path} expired at {NotAfter:u}; replace the file.")]
    private partial void LogExpired(string path, DateTimeOffset notAfter);

    [LoggerMessage(EventId = 24, Level = LogLevel.Warning, Message = "The certificate {Path} expires at {NotAfter:u}, in {Days} days; replace the file before then.")]
    private partial void LogExpiresSoon(string path, DateTimeOffset notAfter, int days);

    [LoggerMessage(EventId = 25, Level = LogLevel.Warning, Message = "The certificate file {Path} holds {Count} certificates besides the server certificate. On Windows they are not sent in the TLS handshake (that would need them added to the machine's certificate store, which this library never does); clients must already have them.")]
    private partial void LogIntermediatesNotSent(string path, int count);

    [LoggerMessage(EventId = 26, Level = LogLevel.Error, Message = "A TLS CA status Changed handler failed.")]
    private partial void LogHandlerFailed(Exception exception);

    /// <summary>What a change of the certificate and key files is detected by.</summary>
    private readonly record struct FileStamp(long Length, DateTime LastWriteUtc, long KeyLength, DateTime KeyLastWriteUtc)
    {
        public static FileStamp Read(string path, string? keyPath)
        {
            (long length, DateTime written) = Of(path);
            (long keyLength, DateTime keyWritten) = keyPath is null ? (0, default) : Of(keyPath);
            return new(length, written, keyLength, keyWritten);
        }

        private static (long Length, DateTime LastWriteUtc) Of(string path)
        {
            try
            {
                FileInfo file = new(path);
                return file.Exists ? (file.Length, file.LastWriteTimeUtc) : (-1, default);
            }
#pragma warning disable CA1031 // An unreadable path counts as missing; loading reports the reason.
            catch (Exception)
#pragma warning restore CA1031
            {
                return (-1, default);
            }
        }
    }
}

/// <summary>Polls the own certificate's files for a change and repeats the expiry warning daily.</summary>
internal sealed class OwnCertificateMonitor(OwnCertificateSource source, TlsCaOptions options, TimeProvider timeProvider) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(options.CertificatePollInterval, timeProvider, stoppingToken).ConfigureAwait(false);
                source.Poll();
                source.CheckExpiry();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }
}
