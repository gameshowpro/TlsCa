namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// What an app may want to show about HTTPS in its own health or status UI. Registered in DI by
/// <c>AddGameshowProTlsCa</c> in every <see cref="TlsCaMode"/>. Read-only.
/// </summary>
public interface ITlsCaStatus
{
    /// <summary>How HTTPS is provided. Fixed for the life of the app.</summary>
    TlsCaMode Mode { get; }

    /// <summary>
    /// The device's mDNS name, <c>&lt;name&gt;.local</c>; <c>""</c> while <see cref="IdentityProblem"/> is set and in every
    /// mode other than <see cref="TlsCaMode.BuiltInCa"/>.
    /// </summary>
    string MdnsName { get; }

    /// <summary>
    /// The HTTPS port: the one the library listens on in <see cref="TlsCaMode.BuiltInCa"/> and
    /// <see cref="TlsCaMode.OwnCertificate"/> (bound even while <see cref="Problem"/> is set); the port of Kestrel's
    /// <c>https</c> endpoint in <see cref="TlsCaMode.KestrelCertificate"/> (<c>0</c> when there is none or it cannot be
    /// read from the configuration); <c>0</c> in <see cref="TlsCaMode.Off"/>.
    /// </summary>
    int HttpsPort { get; }

    /// <summary>A ready-to-open HTTPS root when this library knows a certificate name, else null.</summary>
    string? SecureAddress => null;

    /// <summary>The built-in CA's HTTP management page when its identity and HTTP listener are available, else null.</summary>
    string? SetupAddress => null;

    /// <summary>Another mDNS responder owns the device name. Reported, never resolved by renaming. Only in <see cref="TlsCaMode.BuiltInCa"/>.</summary>
    bool NameConflict { get; }

    /// <summary>
    /// The name the machine would get today when it differs from the stored one (the machine was renamed), else null;
    /// null while <see cref="IdentityProblem"/> is set and outside <see cref="TlsCaMode.BuiltInCa"/>.
    /// </summary>
    string? NameMismatch { get; }

    /// <summary>
    /// The CA certificate's SHA-256 fingerprint, <c>AB:CD:...</c>: what users compare when they install it; <c>""</c>
    /// while <see cref="IdentityProblem"/> is set and outside <see cref="TlsCaMode.BuiltInCa"/>.
    /// </summary>
    string CaFingerprintSha256 { get; }

    /// <summary>
    /// In <see cref="TlsCaMode.BuiltInCa"/>: null when the identity is usable. Otherwise why there is none: the stored
    /// identity could not be read, decrypted or verified, or a first one could not be created. The text holds no key
    /// material. While it is set the app keeps running, HTTPS handshakes fail, the certificate endpoints answer 503, and a
    /// gated reset (the management page opened on this machine) replaces the identity without a restart;
    /// <see cref="Changed"/> is raised when it clears. Always null in the other modes (see <see cref="Problem"/>).
    /// </summary>
    string? IdentityProblem { get; }

    /// <summary>
    /// Why HTTPS cannot serve a certificate, or null: <see cref="IdentityProblem"/> in <see cref="TlsCaMode.BuiltInCa"/>;
    /// in <see cref="TlsCaMode.OwnCertificate"/>, why <see cref="TlsCaOptions.CertificatePath"/> could not be loaded
    /// (names the file, never the password); always null in the other modes. HTTPS handshakes fail while it is set.
    /// </summary>
    string? Problem { get; }

    /// <summary>The own certificate's notAfter in <see cref="TlsCaMode.OwnCertificate"/> while one is loaded, else null.</summary>
    DateTimeOffset? CertificateNotAfter { get; }

    /// <summary>
    /// The DNS names of the own certificate (its subject alternative names) in <see cref="TlsCaMode.OwnCertificate"/>
    /// while one is loaded, else empty.
    /// </summary>
    IReadOnlyList<string> CertificateDnsNames { get; }

    /// <summary>
    /// Raised after any of the values may have changed: the identity was renewed or reset (which clears
    /// <see cref="IdentityProblem"/>), a name conflict appeared or cleared, or the own certificate was loaded again
    /// (successfully or not). Raised on the thread that made the change; a handler that throws is logged and does not
    /// affect HTTPS.
    /// </summary>
    event EventHandler? Changed;
}

/// <summary>Runtime facts the identity itself does not hold, shared between the hosted services and the endpoints.</summary>
internal sealed partial class TlsCaStatus : ITlsCaStatus, IDisposable
{
    private readonly TlsCaModeResolution _resolution;
    private readonly TlsIdentityManager? _manager;
    private readonly OwnCertificateSource? _own;
    private readonly TlsCaOptions _options;
    private readonly ILogger<TlsCaStatus> _logger;
    private int _nameConflict;

    /// <summary>Creates the status for <see cref="TlsCaMode.BuiltInCa"/>.</summary>
    /// <param name="manager">The identity manager.</param>
    /// <param name="options">The effective options.</param>
    /// <param name="logger">Receives handler failures.</param>
    public TlsCaStatus(TlsIdentityManager manager, TlsCaOptions options, ILogger<TlsCaStatus> logger)
        : this(new TlsCaModeResolution(TlsCaMode.BuiltInCa, null, 0), options, manager, null, logger)
    {
    }

    /// <summary>Creates the status for the mode in <paramref name="resolution"/>.</summary>
    /// <param name="resolution">The mode.</param>
    /// <param name="options">The effective options.</param>
    /// <param name="manager">The identity manager, in <see cref="TlsCaMode.BuiltInCa"/> only.</param>
    /// <param name="own">The own certificate, in <see cref="TlsCaMode.OwnCertificate"/> only.</param>
    /// <param name="logger">Receives handler failures.</param>
    public TlsCaStatus(TlsCaModeResolution resolution, TlsCaOptions options, TlsIdentityManager? manager, OwnCertificateSource? own, ILogger<TlsCaStatus> logger)
    {
        _resolution = resolution;
        _options = options;
        _manager = manager;
        _own = own;
        _logger = logger;
        _manager?.Changed += OnIdentityChanged;
        _own?.Changed += OnOwnCertificateChanged;
    }

    public event EventHandler? Changed;

    public TlsCaMode Mode => _resolution.Mode;

    public string MdnsName => _manager?.CurrentOrDefault?.MdnsName ?? "";

    public int HttpsPort => Mode switch
    {
        TlsCaMode.BuiltInCa or TlsCaMode.OwnCertificate => _options.HttpsPort,
        TlsCaMode.KestrelCertificate => _resolution.KestrelHttpsPort,
        TlsCaMode.Off => 0,
        _ => 0,
    };

    public string? SecureAddress
    {
        get
        {
            if (HttpsPort <= 0)
            {
                return null;
            }

            return Mode switch
            {
                TlsCaMode.BuiltInCa when _manager?.CurrentOrDefault is { } identity =>
                    $"https://{identity.MdnsName}:{HttpsPort}/",
                TlsCaMode.OwnCertificate when _own?.Current is { } own =>
                    FirstConcreteDnsName(own.DnsNames) is { } name ? $"https://{name}:{HttpsPort}/" : null,
                TlsCaMode.BuiltInCa or TlsCaMode.OwnCertificate => null,
                TlsCaMode.KestrelCertificate or TlsCaMode.Off => null,
                _ => null,
            };

            // SAN order is certificate order; the first concrete DNS name is the operator's primary address.
            static string? FirstConcreteDnsName(IEnumerable<string> names) => names.FirstOrDefault(
                static name => !name.Contains('*', StringComparison.Ordinal) && Uri.CheckHostName(name) == UriHostNameType.Dns);
        }
    }

    public string? SetupAddress => Mode == TlsCaMode.BuiltInCa && _options.HttpPort > 0 && _manager?.CurrentOrDefault is { } identity
        ? AddressSuggestions.BuildSetupAddress(identity.MdnsName, _options.HttpPort)
        : null;

    public string? NameMismatch => _manager?.CurrentOrDefault is { } identity ? _manager.NameMismatchFor(identity) : null;

    public string CaFingerprintSha256 => _manager?.CurrentOrDefault?.CaFingerprintSha256 ?? "";

    public string? IdentityProblem =>
        _manager is not null && _manager.CurrentOrDefault is null ? _manager.LoadFailure ?? "The TLS identity is not loaded." : null;

    public string? Problem => Mode switch
    {
        TlsCaMode.BuiltInCa => IdentityProblem,
        TlsCaMode.OwnCertificate => _own?.Problem,
        TlsCaMode.KestrelCertificate or TlsCaMode.Off => null,
        _ => null,
    };

    public DateTimeOffset? CertificateNotAfter => _own?.Current?.NotAfter;

    public IReadOnlyList<string> CertificateDnsNames => _own?.Current is { } current ? current.DnsNames : [];

    /// <summary>The own certificate in force, in <see cref="TlsCaMode.OwnCertificate"/>; else null.</summary>
    internal OwnCertificate? OwnCertificate => _own?.Current;

    /// <summary>Another mDNS responder owns the device name. Set by the mDNS service; a change raises <see cref="Changed"/>.</summary>
    public bool NameConflict
    {
        get => Volatile.Read(ref _nameConflict) != 0;
        set
        {
            if (Interlocked.Exchange(ref _nameConflict, value ? 1 : 0) != (value ? 1 : 0))
            {
                RaiseChanged();
            }
        }
    }

    public void Dispose()
    {
        _manager?.Changed -= OnIdentityChanged;
        _own?.Changed -= OnOwnCertificateChanged;
    }

    private void OnIdentityChanged(object? sender, TlsIdentityChangedEventArgs e) => RaiseChanged();

    private void OnOwnCertificateChanged(object? sender, EventArgs e) => RaiseChanged();

    private void RaiseChanged()
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
#pragma warning disable CA1031 // An app's status handler must not break renewal, certificate loading or the mDNS service.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogHandlerFailed(exception);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "A TLS CA status Changed handler failed.")]
    private partial void LogHandlerFailed(Exception exception);
}

/// <summary>Registered by <c>AddGameshowProTlsCa</c> so <c>MapGameshowProTlsCa</c> and <c>UseGameshowProTlsCa</c> can tell it was called.</summary>
internal sealed class TlsCaMarker;
