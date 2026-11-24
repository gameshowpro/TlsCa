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
    /// <item>Only in <see cref="TlsCaMode.BuiltInCa"/>, when <see cref="TlsCaOptions.RedirectHttpRoot"/> is true (the default), a plain-HTTP <c>GET</c> or
    /// <c>HEAD</c> of <c>/</c> whose <c>Host</c> is not a loopback name (see <see cref="LoopbackGate.IsLoopbackHost"/>) is
    /// answered with <c>302</c> and <c>Cache-Control: no-store</c> to <c>http://&lt;host&gt;/.well-known/gameshowpro/</c>,
    /// keeping the <c>Host</c> header's port and the query string. A request without a <c>Host</c> header (HTTP/1.0) uses
    /// the local address it arrived on, and gets 404 when that is unknown. Everything else (HTTPS, other paths, other
    /// methods, loopback hosts) continues down the pipeline.</item>
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
        TlsCaMode mode = app.ApplicationServices.GetRequiredService<TlsCaModeResolution>().Mode;
        _ = app.MapWhen(static context => TlsCaPaths.IsWellKnown(context.Request.Path), static branch => branch.Run(HandleWellKnown));
        if (mode == TlsCaMode.BuiltInCa && options.RedirectHttpRoot)
        {
            _ = app.Use(RedirectHttpRoot);
        }

        return app;
    }

    private static Task HandleWellKnown(HttpContext context)
    {
        // Routing may already have chosen one of the app's endpoints (its fallback, say); that choice does not apply here.
        context.SetEndpoint(null);
        return TlsCaEndpoints.Handle(context);
    }

    private static Task RedirectHttpRoot(HttpContext context, RequestDelegate next)
    {
        HttpRequest request = context.Request;
        if (request.IsHttps || request.Path != s_root || !(HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method)))
        {
            return next(context);
        }

        string? host = RequestHost(context);
        if (LoopbackGate.IsLoopbackHost(host is null ? default : new HostString(host)))
        {
            return next(context);
        }

        if (string.IsNullOrWhiteSpace(host))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return Task.CompletedTask;
        }

        context.Response.Headers.CacheControl = "no-store";
        context.Response.Redirect($"http://{host.Trim()}{TlsCaPaths.WellKnownPrefix}/{request.QueryString.ToUriComponent()}", permanent: false);
        return Task.CompletedTask;

        // Use the Host header, or the local address for HTTP/1.0 requests without one.
        static string? RequestHost(HttpContext context) =>
            context.Request.Host.HasValue
                ? context.Request.Host.Value
                : context.Connection.LocalIpAddress is { } local
                    ? (local.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{local}]" : local.ToString())
                    : null;
    }
}
