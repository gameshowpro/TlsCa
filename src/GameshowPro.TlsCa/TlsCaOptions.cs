namespace GameshowPro.TlsCa;

/// <summary>
/// Configuration for one app's TLS CA. <see cref="TlsIdentityManager"/> uses the naming, time and renewal settings; the
/// ASP.NET Core integration uses the rest (ports, product, version, storage directory).
/// </summary>
public sealed class TlsCaOptions
{
    /// <summary>The default for <see cref="RenewWhenRemaining"/>: 90 days.</summary>
    public static readonly TimeSpan DefaultRenewWhenRemaining = TimeSpan.FromDays(90);

    /// <summary>The default for <see cref="MinimumTime"/>: the time this library was built.</summary>
    public static DateTimeOffset DefaultMinimumTime => BuildInfo.Timestamp;

    /// <summary>The product name shown to users and carried in <c>info.json</c>, for example <c>TriggerGate</c>.</summary>
    public string Product { get; set; } = "";

    /// <summary>
    /// The app label appended to the system host name to form the device name, for example <c>triggergate</c> giving
    /// <c>studio-pc-triggergate</c>. Required unless <see cref="ExplicitName"/> is set.
    /// </summary>
    public string AppLabel { get; set; } = "";

    /// <summary>
    /// A device name to use instead of deriving one from the host name and <see cref="AppLabel"/>, for appliances.
    /// Must be a valid DNS label (see <see cref="DeviceName.IsValidLabel"/>).
    /// </summary>
    public string? ExplicitName { get; set; }

    /// <summary>The directory holding the identity file. It is created, and its permissions restricted, on first use.</summary>
    public string StorageDirectory { get; set; } = "";

    /// <summary>The plain-HTTP port serving the certificate management page.</summary>
    public int HttpPort { get; set; }

    /// <summary>
    /// The HTTPS port served with the leaf certificate (or with <see cref="CertificatePath"/>). With the ASP.NET Core
    /// integration, <c>0</c> means HTTPS is off (<see cref="TlsCaMode.Off"/>), and
    /// <c>&lt;ConfigurationSection&gt;:HttpsPort</c> overrides this value.
    /// </summary>
    public int HttpsPort { get; set; }

    /// <summary>
    /// The app's own server certificate: a PKCS#12 file (<c>.pfx</c>, <c>.p12</c>), or a PEM file holding the certificate
    /// first and then any intermediates (and the private key, unless <see cref="CertificateKeyPath"/> is set). When set,
    /// and HTTPS is not off, the ASP.NET Core integration runs in <see cref="TlsCaMode.OwnCertificate"/>: it serves this
    /// certificate on <see cref="HttpsPort"/> and creates no CA. A relative path is relative to the app's content root.
    /// <c>&lt;ConfigurationSection&gt;:CertificatePath</c> overrides this value.
    /// </summary>
    public string? CertificatePath { get; set; }

    /// <summary>
    /// The PEM private key of <see cref="CertificatePath"/> when it is in a separate file; requires
    /// <see cref="CertificatePath"/>. <c>&lt;ConfigurationSection&gt;:CertificateKeyPath</c> overrides this value.
    /// </summary>
    public string? CertificateKeyPath { get; set; }

    /// <summary>
    /// The password of a PKCS#12 <see cref="CertificatePath"/>, or of an encrypted PEM private key (<c>ENCRYPTED PRIVATE
    /// KEY</c>). <c>&lt;ConfigurationSection&gt;:CertificatePassword</c> overrides this value. Never logged or served.
    /// </summary>
    public string? CertificatePassword { get; set; }

    /// <summary>
    /// The app version carried in <c>info.json</c>. When null, the ASP.NET Core integration uses the entry assembly's
    /// informational version without its <c>+metadata</c> suffix (else its assembly version).
    /// </summary>
    public string? Version { get; set; }

    /// <summary>
    /// The app's configuration section for TLS settings, for example <c>TriggerGate</c>. When set, the ASP.NET Core
    /// integration reads <c>&lt;section&gt;:HttpsPort</c> (overrides <see cref="HttpsPort"/>; <c>0</c> turns HTTPS off; any
    /// other value outside 1 to 65535, or a value that is not a number, is an error),
    /// <c>&lt;section&gt;:TlsStorageDirectory</c> (overrides <see cref="StorageDirectory"/>), and
    /// <c>&lt;section&gt;:CertificatePath</c>, <c>CertificateKeyPath</c> and <c>CertificatePassword</c> (override the
    /// options of the same names). Blank values are ignored.
    /// </summary>
    public string? ConfigurationSection { get; set; }

    /// <summary>
    /// When true (the default), <see cref="TlsCaApplicationBuilderExtensions.UseGameshowProTlsCa"/> redirects a plain-HTTP
    /// <c>GET</c> or <c>HEAD</c> of <c>/</c> from any host other than this machine's loopback names to the management page,
    /// which tells the browser how to trust the CA, or forwards it to HTTPS when it already does.
    /// </summary>
    public bool RedirectHttpRoot { get; set; } = true;

    /// <summary>
    /// Redirect plain-HTTP browser page navigations outside the management prefix to that page in
    /// <see cref="TlsCaMode.BuiltInCa"/>. The original safe path and query are supplied as <c>returnTo</c>.
    /// API requests and non-navigation requests continue to the app. Default true.
    /// </summary>
    public bool RedirectHttpNavigations { get; set; } = true;

    /// <summary>
    /// Redirect an HTTPS browser page navigation on a name other than the built-in certificate's mDNS name to
    /// the management page on the same host, preserving a safe path and query for forwarding after a trust probe.
    /// Loopback hosts and management endpoints are exempt. Default true.
    /// </summary>
    public bool RedirectHttpsHost { get; set; } = true;

    /// <summary>
    /// Redirect plain-HTTP browser page navigations in <see cref="TlsCaMode.OwnCertificate"/> to the HTTPS port
    /// on the same host, only when that host matches a DNS subject alternative name of the loaded certificate.
    /// Loopback hosts and management endpoints are exempt. Default true.
    /// </summary>
    public bool RedirectOwnCertificateHttp { get; set; } = true;

    /// <summary>
    /// Let a browser remain on its current address after the user chooses the management page's HTTP fallback.
    /// When true (the default), a session cookie named <c>gsp-tlsca-http</c> with value <c>1</c> suppresses the
    /// built-in CA's HTTP navigation and wrong-host HTTPS redirects. It never changes the management endpoints or gate.
    /// Set false to require redirects even when a browser sends this cookie.
    /// </summary>
    public bool AllowHttpFallback { get; set; } = true;

    /// <summary>
    /// Let a browser continue on a non-canonical HTTPS host after the management page's trust probe fails.
    /// When true (the default), a session cookie named <c>gsp-tlsca-https</c> with value <c>1</c> suppresses
    /// only the built-in CA's wrong-host HTTPS navigation redirect. The page sets this cookie over HTTPS with
    /// <c>Secure</c>. HTTP navigation redirects, management endpoints and the gate are unaffected.
    /// </summary>
    public bool AllowHttpsFallback { get; set; } = true;

    /// <summary>
    /// The earliest time used for issuing: a system clock earlier than this is treated as this time. Defaults to
    /// <see cref="DefaultMinimumTime"/>, the library's build time.
    /// </summary>
    public DateTimeOffset MinimumTime { get; set; } = DefaultMinimumTime;

    /// <summary>The leaf is renewed automatically when less than this remains of its validity. Defaults to 90 days.</summary>
    public TimeSpan RenewWhenRemaining { get; set; } = DefaultRenewWhenRemaining;

    /// <summary>
    /// Decides whether a request to renew the leaf or reset the identity may proceed. Null (the default) uses
    /// <see cref="LoopbackGate"/>: the request must come from the machine itself.
    /// </summary>
    public ITlsCaGate? Gate { get; set; }

    /// <summary>
    /// Advertises the device name, <c>_https._tcp</c> and <c>_http._tcp</c> over mDNS (default true). Turn it off for
    /// tests, or when the app advertises the name itself.
    /// </summary>
    public bool AdvertiseMdns { get; set; } = true;

    /// <summary>
    /// Where the mDNS advertisement runs (with <see cref="AdvertiseMdns"/>). Null (the default): on every interface
    /// GameshowPro.Mdns finds eligible. Empty: nowhere, for as long as it stays empty. Otherwise one advertisement (the
    /// <c>_https._tcp</c> and <c>_http._tcp</c> pair) per scope, each started, retried and reporting a name conflict on
    /// its own; duplicates count once. Use one scope per interface.
    /// <para>
    /// May be replaced from any thread while the app runs, on the options instance the library keeps: the advertisement
    /// follows within two seconds, withdrawing scopes that left the list and starting new ones, while scopes still in the
    /// list keep running untouched. The list is copied when set, so change it by setting a new one. This affects mDNS
    /// only: the HTTPS listener still accepts connections on every interface.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentException">The list holds a null element.</exception>
    public IReadOnlyList<TlsCaMdnsScope>? MdnsScopes
    {
        get => Volatile.Read(ref field);
        set
        {
            if (value is null)
            {
                Volatile.Write(ref field, null);
                return;
            }

            if (value.Any(scope => scope is null))
            {
                throw new ArgumentException("MdnsScopes cannot hold a null element.", nameof(value));
            }

            ImmutableArray<TlsCaMdnsScope> copy = [.. value];
            IReadOnlyList<TlsCaMdnsScope> snapshot = copy;
            Volatile.Write(ref field, snapshot);
        }
    }

    /// <summary>Test seam: the key protector the ASP.NET Core integration gives its store, instead of the platform default.</summary>
    internal IKeyProtector? KeyProtectorOverride { get; set; }

    /// <summary>Test seam: how often <see cref="CertificatePath"/> (and its key file) is checked for a change.</summary>
    internal TimeSpan CertificatePollInterval { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Test seam: replaces <see cref="ServerCertificateFactory.Create"/> in <see cref="TlsIdentityManager"/>.</summary>
    internal Func<X509Certificate2, ECDsa, X509Certificate2>? ServerCertificateFactoryOverride { get; set; }
}
