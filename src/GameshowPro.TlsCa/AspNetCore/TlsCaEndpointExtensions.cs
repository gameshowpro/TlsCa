namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>Maps the certificate management endpoints and page with endpoint routing.</summary>
public static class TlsCaEndpointExtensions
{
    /// <summary>
    /// Maps, under <c>/.well-known/gameshowpro/</c>: the management page (<c>GET /.well-known/gameshowpro/</c>),
    /// <c>ca.crt</c> (DER), <c>ca.pem</c>, <c>ca.mobileconfig</c>, <c>info.json</c>, and the gated <c>POST renew</c> and
    /// <c>POST reset</c>. Every response carries <c>Cache-Control: no-store</c>. The GET endpoints and the page are open
    /// to anyone on the LAN, over HTTP and HTTPS; <c>info.json</c> allows any origin (for the trust probe). The POSTs
    /// accept only <c>application/json</c> (415 otherwise) and pass the <see cref="ITlsCaGate"/> (403 otherwise);
    /// a CORS preflight is never granted. No endpoint returns a private key or signs anything a client supplies.
    /// </summary>
    /// <remarks>
    /// Most apps call <see cref="TlsCaApplicationBuilderExtensions.UseGameshowProTlsCa"/> instead, which serves the same
    /// endpoints ahead of the app's own routing and fallback. This method is for apps that prefer endpoint routing; it
    /// requires <c>AddGameshowProTlsCa</c>. Unknown paths under the prefix are left to the app. Outside
    /// <see cref="TlsCaMode.BuiltInCa"/> the same paths answer as described at
    /// <see cref="TlsCaApplicationBuilderExtensions.UseGameshowProTlsCa"/>.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The CA was not added to the app.</exception>
    public static IEndpointRouteBuilder MapGameshowProTlsCa(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        if (endpoints.ServiceProvider.GetService<TlsCaMarker>() is null)
        {
            throw new InvalidOperationException($"Call {nameof(TlsCaBuilderExtensions.AddGameshowProTlsCa)} on the WebApplicationBuilder before {nameof(MapGameshowProTlsCa)}.");
        }

        // One handler for every method: it answers a known path with the wrong method (a CORS preflight included) with a
        // 405 that grants nothing. RequestDelegate endpoints need no minimal-API binding, so this is Native AOT safe.
        foreach (string path in TlsCaEndpoints.Paths)
        {
            _ = endpoints.Map(TlsCaPaths.WellKnownPrefix + path, TlsCaEndpoints.Handler);
        }

        return endpoints;
    }
}

/// <summary>Serves the certificate management endpoints and page from the request pipeline.</summary>
public static class TlsCaApplicationBuilderExtensions
{
    private static readonly PathString s_root = new("/");

    /// <summary>
    /// Serves the certificate endpoints from the request pipeline, in every <see cref="TlsCaMode"/>. Call it
    /// unconditionally, early in the pipeline (before the app's own redirects, routing endpoints and fallback).
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>Every request under <c>/.well-known/gameshowpro</c>, on every listener, is answered here and goes no further,
    /// whatever the app's own routing, redirects or fallback would do with it. In <see cref="TlsCaMode.BuiltInCa"/> the
    /// endpoints are those described at <see cref="TlsCaEndpointExtensions.MapGameshowProTlsCa"/>. In the other modes the
    /// page is replaced by a short static notice (same headers), <c>ca.crt</c>, <c>ca.pem</c> and <c>ca.mobileconfig</c>
    /// answer 404 with a fixed text, <c>renew</c> and <c>reset</c> answer 409 with an <c>error</c> document (415 first for a
    /// body that is not JSON; no gate is asked), and <c>info.json</c> answers 200 without CA fields. An unknown path under
    /// the prefix gets 404.</item>
    /// <item>In <see cref="TlsCaMode.BuiltInCa"/>, a plain-HTTP browser GET or HEAD navigation reaches the management
    /// page, with its safe original path and query in <c>returnTo</c>. <see cref="TlsCaOptions.RedirectHttpRoot"/> also
    /// covers root GET and HEAD requests without navigation headers. A request without a Host header uses its local
    /// address and gets 404 when that is unknown. A browser navigation over HTTPS on a wrong host reaches the same
    /// host's management page, which probes the built-in certificate name before forwarding.
    /// In <see cref="TlsCaMode.OwnCertificate"/>, an HTTP navigation redirects to HTTPS on the same host only when it
    /// matches a DNS name of the loaded certificate. Loopback hosts and management paths always continue unchanged.
    /// The redirect behaviors have separate options on <see cref="TlsCaOptions"/>.</item>
    /// </list>
    /// Only request delegates are used (no minimal-API binding), so this is Native AOT safe.
    /// </remarks>
    /// <exception cref="InvalidOperationException"><c>AddGameshowProTlsCa</c> was not called.</exception>
    public static IApplicationBuilder UseGameshowProTlsCa(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (app.ApplicationServices.GetService<TlsCaMarker>() is null)
        {
            throw new InvalidOperationException($"Call {nameof(TlsCaBuilderExtensions.AddGameshowProTlsCa)} on the WebApplicationBuilder before {nameof(UseGameshowProTlsCa)}.");
        }

        TlsCaOptions options = app.ApplicationServices.GetRequiredService<TlsCaOptions>();
        TlsCaStatus status = app.ApplicationServices.GetRequiredService<TlsCaStatus>();
        _ = app.MapWhen(static context => TlsCaPaths.IsWellKnown(context.Request.Path), static branch => branch.Run(HandleWellKnown));
        if (status.Mode is TlsCaMode.BuiltInCa or TlsCaMode.OwnCertificate)
        {
            _ = app.Use(Redirect);
        }

        return app;

        Task Redirect(HttpContext context, RequestDelegate next)
        {
            HttpRequest request = context.Request;
            if (status.Mode == TlsCaMode.BuiltInCa && options.AllowHttpFallback
                && request.Cookies.TryGetValue("gsp-tlsca-http", out string? fallback) && fallback == "1")
            {
                return next(context);
            }

            if (!SafePathAndQuery(request, out string pathAndQuery))
            {
                return next(context);
            }

            HostString host = RequestHost(context);
            if (LoopbackGate.IsLoopbackHost(host))
            {
                return next(context);
            }

            bool navigation = IsBrowserNavigation(request);
            if (request.IsHttps)
            {
                if (status.Mode == TlsCaMode.BuiltInCa && options.RedirectHttpsHost
                    && navigation && host.HasValue
                    && status.MdnsName is { Length: > 0 } canonical
                    && !host.Host.Equals(canonical, StringComparison.OrdinalIgnoreCase)
                    && !(options.AllowHttpsFallback
                        && request.Cookies.TryGetValue("gsp-tlsca-https", out string? httpsFallback)
                        && httpsFallback == "1"))
                {
                    return RedirectTo($"https://{host.ToUriComponent()}{TlsCaPaths.WellKnownPrefix}/?returnTo={Uri.EscapeDataString(pathAndQuery)}");
                }

                return next(context);
            }

            if (status.Mode == TlsCaMode.BuiltInCa)
            {
                bool root = request.Path == s_root;
                bool redirect = root
                    ? options.RedirectHttpRoot && (navigation || !ExplicitNonNavigation(request))
                    : options.RedirectHttpNavigations && navigation;
                if (redirect)
                {
                    return host.HasValue
                        ? RedirectTo($"http://{host.ToUriComponent()}{TlsCaPaths.WellKnownPrefix}/?returnTo={Uri.EscapeDataString(pathAndQuery)}")
                        : NotFound();
                }
            }
            else if (status.Mode == TlsCaMode.OwnCertificate && options.RedirectOwnCertificateHttp && navigation
                     && status.HttpsPort is > 0 && host.HasValue && HostMatchesCertificate(host.Host, status.CertificateDnsNames))
            {
                return RedirectTo($"https://{new HostString(host.Host, status.HttpsPort).ToUriComponent()}{pathAndQuery}");
            }

            return next(context);

            Task RedirectTo(string location)
            {
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Redirect(location, permanent: false);
                return Task.CompletedTask;
            }

            Task NotFound()
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return Task.CompletedTask;
            }
        }

        static Task HandleWellKnown(HttpContext context)
        {
            // Routing may already have chosen one of the app's endpoints (its fallback, say); that choice does not apply here.
            context.SetEndpoint(null);
            return TlsCaEndpoints.Handle(context);
        }

        static HostString RequestHost(HttpContext context)
        {
            if (context.Request.Host.HasValue)
            {
                return context.Request.Host;
            }

            return context.Connection.LocalIpAddress is { } local
                ? new HostString(local.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{local}]" : local.ToString())
                : default;
        }

        static bool IsBrowserNavigation(HttpRequest request)
        {
            if (!(HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method)))
            {
                return false;
            }

            string mode = request.Headers["Sec-Fetch-Mode"].ToString();
            if (mode.Length > 0)
            {
                return mode.Equals("navigate", StringComparison.OrdinalIgnoreCase)
                    && (request.Headers["Sec-Fetch-Dest"].ToString().Equals("document", StringComparison.OrdinalIgnoreCase)
                        || request.Headers["Sec-Fetch-Dest"].ToString().Equals("iframe", StringComparison.OrdinalIgnoreCase));
            }

            string destination = request.Headers["Sec-Fetch-Dest"].ToString();
            if (destination.Length > 0 && !destination.Equals("document", StringComparison.OrdinalIgnoreCase)
                && !destination.Equals("iframe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            try
            {
                return request.GetTypedHeaders().Accept?.Any(mediaType =>
                    mediaType.MediaType.ToString().Equals("text/html", StringComparison.OrdinalIgnoreCase)
                    && mediaType.Quality is null or > 0) == true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        static bool ExplicitNonNavigation(HttpRequest request) =>
            !(HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method))
            || request.Headers.ContainsKey("Sec-Fetch-Mode") && !IsBrowserNavigation(request)
            || request.Headers.ContainsKey("Sec-Fetch-Dest") && !IsBrowserNavigation(request)
            || request.Headers.Accept.Count > 0 && !IsBrowserNavigation(request)
               && !request.Headers.Accept.ToString().Equals("*/*", StringComparison.Ordinal);

        static bool HostMatchesCertificate(string host, IReadOnlyList<string> dnsNames) =>
            dnsNames.Any(name => name.Equals(host, StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("*.", StringComparison.Ordinal)
                    && host.EndsWith(name[1..], StringComparison.OrdinalIgnoreCase)
                    && host.Length > name.Length - 1
                    && !host[..(host.Length - name.Length + 1)].Contains('.'));

        static bool SafePathAndQuery(HttpRequest request, out string pathAndQuery)
        {
            string path = request.PathBase.ToUriComponent() + request.Path.ToUriComponent();
            if (path.Length == 0)
            {
                path = "/";
            }

            string decoded = path;
            for (int pass = 0; pass < 2; pass++)
            {
                decoded = Uri.UnescapeDataString(decoded);
                if (!decoded.StartsWith('/') || decoded.StartsWith("//", StringComparison.Ordinal)
                    || decoded.Contains('\\') || decoded.Any(char.IsControl))
                {
                    pathAndQuery = "";
                    return false;
                }
            }

            pathAndQuery = path + request.QueryString.ToUriComponent();
            return !pathAndQuery.Any(char.IsControl);
        }
    }
}
