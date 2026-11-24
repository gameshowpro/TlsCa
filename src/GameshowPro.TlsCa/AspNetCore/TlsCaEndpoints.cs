namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// The endpoint handlers, behind one <see cref="RequestDelegate"/> (<see cref="Handle"/>) that dispatches on the path and
/// method, so nothing depends on reflection-based or generated minimal-API binding (Native AOT). Nothing here reads a
/// key, and nothing from a request reaches certificate construction.
/// </summary>
internal static partial class TlsCaEndpoints
{
    private const string PageResourceName = "GameshowPro.TlsCa.management.html";

    private const string NoticeResourceName = "GameshowPro.TlsCa.notice.html";

    /// <summary>The body of the 404 for a CA certificate download outside <see cref="TlsCaMode.BuiltInCa"/>.</summary>
    private const string NoCaCertificateMessage =
        "This installation does not use a GameshowPro certificate authority, so there is no CA certificate to download.";

    /// <summary>The <c>error</c> of the 409 for a renew or reset outside <see cref="TlsCaMode.BuiltInCa"/>.</summary>
    private const string NoCaChangeMessage =
        "This installation does not use a GameshowPro certificate authority, so there is nothing to renew or reset.";

    private const string ReadMethods = "GET, HEAD";

    /// <summary>The body of every 503 while no identity is in force. Fixed text: the reason (which names local paths) is only logged.</summary>
    private const string UnavailableMessage =
        "The TLS identity cannot be used; see the application log. A gated reset creates a new one.";

    /// <summary>The paths below <see cref="TlsCaPaths.WellKnownPrefix"/> that are served; <c>/</c> is the page.</summary>
    public static readonly ImmutableArray<string> Paths = ["/", "/ca.crt", "/ca.pem", "/ca.mobileconfig", "/info.json", "/renew", "/reset"];

    /// <summary><see cref="Handle"/> as a typed delegate, so endpoint mapping picks the <see cref="RequestDelegate"/> overloads.</summary>
    public static readonly RequestDelegate Handler = Handle;

    // The page runs only its own inline script and style, talks only to its own origin and to the HTTPS twin of the
    // device (the trust probe), and cannot be framed (the Reset button is behind a gate that trusts the local browser).
    private const string PageContentSecurityPolicy =
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' https:; "
        + "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    private static readonly Lazy<byte[]> s_page = new(LoadPage);

    private static readonly Lazy<byte[]> s_notice = new(LoadNotice);

    /// <summary>
    /// Serves a request under <see cref="TlsCaPaths.WellKnownPrefix"/>: every response carries <c>Cache-Control: no-store</c>;
    /// a known path with the wrong method gets 405 with <c>Allow</c> (a CORS preflight included, so it grants nothing); an
    /// unknown path gets 404. Paths are case-insensitive and may end in one <c>/</c>, as with endpoint routing.
    /// </summary>
    public static async Task Handle(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        IResult result = await Dispatch(context).ConfigureAwait(false);
        await result.ExecuteAsync(context).ConfigureAwait(false);

        static Task<IResult> Dispatch(HttpContext context)
        {
            if (!context.Request.Path.StartsWithSegments(TlsCaPaths.WellKnownPrefix, StringComparison.OrdinalIgnoreCase, out PathString rest))
            {
                return Task.FromResult(Results.NotFound());
            }

            // "" and "/" are the page; otherwise one trailing slash is ignored.
            string path = rest.Value is { Length: > 1 } value ? (value.EndsWith('/') ? value[..^1] : value) : "/";
            IServiceProvider services = context.RequestServices;
            TlsCaStatus status = services.GetRequiredService<TlsCaStatus>();
            bool ca = status.Mode == TlsCaMode.BuiltInCa;
            string method = context.Request.Method;
            bool read = HttpMethods.IsGet(method) || HttpMethods.IsHead(method);
            bool post = HttpMethods.IsPost(method);
            if (Is("/"))
            {
                return Read(() => ca ? Page(context) : Notice(context));
            }

            if (Is("/ca.crt"))
            {
                return Read(() => ca ? WithIdentity(services, CaDer) : NoCaCertificate());
            }

            if (Is("/ca.pem"))
            {
                return Read(() => ca ? WithIdentity(services, CaPem) : NoCaCertificate());
            }

            if (Is("/ca.mobileconfig"))
            {
                return Read(() => ca ? WithIdentity(services, CaMobileConfig) : NoCaCertificate());
            }

            if (Is("/info.json"))
            {
                return Read(() => ca ? Info(context, services) : CertificateInfo(context, services, status));
            }

            if (Is("/renew") || Is("/reset"))
            {
                return !post
                    ? Task.FromResult(MethodNotAllowed(context, "POST"))
                    : ca ? Change(context, services, reset: Is("/reset")) : Task.FromResult(NoCaChange(context));
            }

            return Task.FromResult(Results.NotFound());

            bool Is(string candidate) => path.Equals(candidate, StringComparison.OrdinalIgnoreCase);

            Task<IResult> Read(Func<IResult> handler) => Task.FromResult(read ? handler() : MethodNotAllowed(context, ReadMethods));

            static IResult Page(HttpContext context)
            {
                context.Response.Headers.ContentSecurityPolicy = PageContentSecurityPolicy;
                context.Response.Headers.XContentTypeOptions = "nosniff";
                return Results.Bytes(s_page.Value, "text/html; charset=utf-8");
            }

            // The static notice outside BuiltInCa carries the same headers as the management page.
            static IResult Notice(HttpContext context)
            {
                context.Response.Headers.ContentSecurityPolicy = PageContentSecurityPolicy;
                context.Response.Headers.XContentTypeOptions = "nosniff";
                return Results.Bytes(s_notice.Value, "text/html; charset=utf-8");
            }

            // Other HTTPS modes expose only the public certificate metadata, never a path or exception text.
            static IResult CertificateInfo(HttpContext context, IServiceProvider services, TlsCaStatus status)
            {
                context.Response.Headers.AccessControlAllowOrigin = "*";
                TlsCaOptions options = services.GetRequiredService<TlsCaOptions>();
                OwnCertificate? own = status.OwnCertificate;
                string[] fallbackAddresses = FallbackAddresses(context, options);
                CertificateInfoDocument document = new(
                    options.Product,
                    status.HttpsPort,
                    options.Version,
                    CertificateSources.For(status.Mode),
                    own?.NotAfter.ToUnixTimeSeconds(),
                    own is null ? null : [.. own.DnsNames],
                    status.SecureAddress,
                    status.SetupAddress,
                    fallbackAddresses.Length == 1 ? fallbackAddresses[0] : null,
                    fallbackAddresses,
                    false);
                return Results.Json(document, TlsCaJsonContext.Default.CertificateInfoDocument);
            }

            // Renew and reset outside BuiltInCa answer 415 unless JSON, then 409. No gate is asked.
            static IResult NoCaChange(HttpContext context) =>
                IsJson(context.Request.ContentType)
                    ? Results.Json(new ErrorDocument(NoCaChangeMessage), TlsCaJsonContext.Default.ErrorDocument, statusCode: StatusCodes.Status409Conflict)
                    : Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);

            static IResult Info(HttpContext context, IServiceProvider services)
            {
                // The trust probe fetches this from the HTTP page. It carries nothing secret.
                context.Response.Headers.AccessControlAllowOrigin = "*";
                if (CreateInfo(context, services) is { } info)
                {
                    return Results.Json(info, TlsCaJsonContext.Default.InfoDocument);
                }

                TlsCaOptions options = services.GetRequiredService<TlsCaOptions>();
                string[] fallbackAddresses = FallbackAddresses(context, options);
                UnavailableDocument unavailable = new(UnavailableMessage, IdentityUnavailable: true, options.Product, options.HttpsPort, options.Version, services.GetRequiredService<ITlsCaGate>().Kind, CertificateSources.Ca, null, null, fallbackAddresses.Length == 1 ? fallbackAddresses[0] : null, fallbackAddresses, options.AllowHttpFallback);
                return Results.Json(unavailable, TlsCaJsonContext.Default.UnavailableDocument, statusCode: StatusCodes.Status503ServiceUnavailable);
            }
        }
    }

    private static IResult MethodNotAllowed(HttpContext context, string allow)
    {
        context.Response.Headers.Allow = allow;
        return Results.StatusCode(StatusCodes.Status405MethodNotAllowed);
    }

    private static IResult NoCaCertificate() =>
        Results.Text(NoCaCertificateMessage, "text/plain; charset=utf-8", statusCode: StatusCodes.Status404NotFound);

    /// <summary>Runs <paramref name="handler"/> on the identity in force, or answers 503 when there is none.</summary>
    private static IResult WithIdentity(IServiceProvider services, Func<TlsIdentity, IResult> handler) =>
        services.GetRequiredService<TlsIdentityManager>().CurrentOrDefault is { } identity
            ? handler(identity)
            : Results.Text(UnavailableMessage, "text/plain; charset=utf-8", statusCode: StatusCodes.Status503ServiceUnavailable);

    private static IResult CaDer(TlsIdentity identity) =>
        Results.Bytes([.. identity.CaCertificateDer], "application/x-x509-ca-cert", $"{identity.Name}-ca.crt");

    private static IResult CaPem(TlsIdentity identity)
    {
        string pem = PemEncoding.WriteString("CERTIFICATE", identity.CaCertificateDer.AsSpan()) + "\n";
        return Results.Bytes(Encoding.ASCII.GetBytes(pem), "application/x-pem-file", $"{identity.Name}-ca.pem");
    }

    private static IResult CaMobileConfig(TlsIdentity identity) =>
        Results.Bytes(AppleProfile.Build(identity), AppleProfile.ContentType);

    /// <summary>The document for the identity in force, or null when there is none.</summary>
    private static InfoDocument? CreateInfo(HttpContext context, IServiceProvider services)
    {
        TlsIdentityManager manager = services.GetRequiredService<TlsIdentityManager>();
        return manager.CurrentOrDefault is { } identity
            ? InfoDocument.Create(
                identity,
                manager,
                services.GetRequiredService<TlsCaOptions>(),
                services.GetRequiredService<ITlsCaGate>(),
                services.GetRequiredService<TlsCaStatus>(),
                FallbackAddresses(context, services.GetRequiredService<TlsCaOptions>()))
            : null;
    }

    private static string[] FallbackAddresses(HttpContext context, TlsCaOptions options)
    {
        if (options.HttpPort <= 0)
        {
            return [];
        }

        IReadOnlyList<TlsCaMdnsScope>? scopes = options.MdnsScopes;
        if (scopes is not null)
        {
            return AddressSuggestions.FallbackAddresses(context.Connection.LocalIpAddress, scopes, [], options.HttpPort);
        }

        string[] direct = AddressSuggestions.FallbackAddresses(context.Connection.LocalIpAddress, null, [], options.HttpPort);
        return direct.Length > 0
            ? direct
            : AddressSuggestions.FallbackAddresses(null, null, AddressSuggestions.OperationalNetworks(), options.HttpPort);
    }

    private static Task<IResult> Change(HttpContext context, IServiceProvider services, bool reset) =>
        Change(
            context,
            services.GetRequiredService<TlsIdentityManager>(),
            services.GetRequiredService<ITlsCaGate>(),
            services.GetRequiredService<ILogger<TlsCaMarker>>(),
            () => CreateInfo(context, services),
            reset);

    /// <summary>
    /// Renew the leaf or reset the identity: 415 unless JSON, 403 unless the gate passes. The body is not read. While no
    /// identity is in force only a reset is possible (a renew answers 503), and the gate is asked
    /// <see cref="ITlsCaGate.IsAllowedWithoutIdentity"/>.
    /// </summary>
    private static async Task<IResult> Change(HttpContext context, TlsIdentityManager manager, ITlsCaGate gate, ILogger logger, Func<InfoDocument?> info, bool reset)
    {
        string action = reset ? "reset" : "renew";
        // Only application/json is accepted. A browser must preflight that type on a cross-site request, and a
        // preflight is never granted, so another site cannot trigger this through the local browser.
        if (!IsJson(context.Request.ContentType))
        {
            return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        }

        TlsIdentity? identity = manager.CurrentOrDefault;
        if (identity is null && !reset)
        {
            return Results.Json(new ErrorDocument(UnavailableMessage), TlsCaJsonContext.Default.ErrorDocument, statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        bool allowed = identity is null
            ? await gate.IsAllowedWithoutIdentity(context).ConfigureAwait(false)
            : await gate.IsAllowed(context, identity).ConfigureAwait(false);
        if (!allowed)
        {
            LogRefused(logger, action, context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        // The time in the body is accepted for wire compatibility with the ESP32 and ignored: a PC has a clock.
        try
        {
            _ = reset
                ? await manager.ResetIdentity(context.RequestAborted).ConfigureAwait(false)
                : await manager.RenewLeaf(context.RequestAborted).ConfigureAwait(false);
        }
        catch (ArgumentException exception)
        {
            // The CA has expired: only a reset helps.
            LogFailed(logger, action, exception);
            return Results.Json(new ErrorDocument("The CA has expired; reset the identity instead."), TlsCaJsonContext.Default.ErrorDocument, statusCode: StatusCodes.Status409Conflict);
        }
#pragma warning disable CA1031 // The response never carries exception text; the detail goes to the log, which holds no key material.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogFailed(logger, action, exception);
            return Results.Json(new ErrorDocument("The operation failed; see the application log."), TlsCaJsonContext.Default.ErrorDocument, statusCode: StatusCodes.Status500InternalServerError);
        }

        LogChanged(logger, action, context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        return info() is { } document
            ? Results.Json(document, TlsCaJsonContext.Default.InfoDocument)
            : Results.Json(new ErrorDocument("The operation failed; see the application log."), TlsCaJsonContext.Default.ErrorDocument, statusCode: StatusCodes.Status500InternalServerError);
    }

    private static bool IsJson(string? contentType) =>
        MediaTypeHeaderValue.TryParse(contentType, out MediaTypeHeaderValue? mediaType)
        && mediaType.MediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase);

    private static byte[] LoadPage() => LoadResource(PageResourceName);

    private static byte[] LoadNotice() => LoadResource(NoticeResourceName);

    private static byte[] LoadResource(string name)
    {
        using Stream stream = typeof(TlsCaEndpoints).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"The embedded resource {name} is missing from the assembly.");
        using MemoryStream copy = new();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    [LoggerMessage(EventId = 1, Level = LogLevel.Warning, Message = "Refused a request to {Action} the TLS identity from {Remote}: the gate did not pass.")]
    private static partial void LogRefused(ILogger logger, string action, string remote);

    [LoggerMessage(EventId = 2, Level = LogLevel.Warning, Message = "Performed a gated {Action} of the TLS identity for a request from {Remote}.")]
    private static partial void LogChanged(ILogger logger, string action, string remote);

    [LoggerMessage(EventId = 3, Level = LogLevel.Error, Message = "The {Action} of the TLS identity failed.")]
    private static partial void LogFailed(ILogger logger, string action, Exception exception);
}
