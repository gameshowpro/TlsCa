namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// <c>UseGameshowProTlsCa</c> in front of an app's own pipeline: the well-known paths win over the app's routing,
/// fallback and redirects, and browser navigations reach the secure name through the management page.
/// </summary>
[TestClass]
public sealed class PipelineTests
{
    private const string Prefix = "/.well-known/gameshowpro";

    /// <summary>How the app's own pipeline, after <c>UseGameshowProTlsCa</c>, answers everything else.</summary>
    public enum AppPipeline
    {
        /// <summary>Endpoint routing with a fallback (implicit <c>UseRouting</c> at the start of the pipeline).</summary>
        Fallback,

        /// <summary>The app calls <c>UseRouting</c> itself before <c>UseGameshowProTlsCa</c> and maps a fallback.</summary>
        RoutingFirst,

        /// <summary>A terminal middleware that redirects every request elsewhere (like a separate UI port).</summary>
        RedirectEverything,
    }

    private sealed class App(WebApplication web, TempDirectory directory) : IAsyncDisposable
    {
        private readonly TempDirectory _directory = directory;

        public WebApplication Web { get; } = web;

        public async ValueTask DisposeAsync()
        {
            await Web.StopAsync();
            await Web.DisposeAsync();
            _directory.Dispose();
        }
    }

    private static async Task<App> Start(AppPipeline pipeline = AppPipeline.Fallback, Action<TlsCaOptions>? configure = null, bool tlsCa = true, TlsCaMode? expectedMode = null)
    {
        TempDirectory directory = new();
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.Logging.ClearProviders();
        _ = builder.WebHost.UseTestServer();
        if (expectedMode == TlsCaMode.KestrelCertificate)
        {
            _ = builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Kestrel:Endpoints:Https:Url"] = "https://*:9443" });
        }

        TlsCaMode mode = builder.AddGameshowProTlsCa(ConfigureOptions);
        Assert.AreEqual(expectedMode ?? (tlsCa ? TlsCaMode.BuiltInCa : TlsCaMode.Off), mode);
        WebApplication app = builder.Build();
        // TestServer has no remote address; the gate needs a loopback one for the POST tests.
        _ = app.Use(SetLoopbackRemoteAddress);
        if (pipeline == AppPipeline.RoutingFirst)
        {
            _ = app.UseRouting();
        }

        _ = app.UseGameshowProTlsCa();
        if (pipeline == AppPipeline.RedirectEverything)
        {
            app.Run(RedirectEverything);
        }
        else
        {
            _ = app.MapFallback("{**path}", context => context.Response.WriteAsync($"fallback {context.Request.Method} {context.Request.Path}"));
        }

        await app.StartAsync();
        return new(app, directory);

        void ConfigureOptions(TlsCaOptions options)
        {
            options.Product = "TriggerGate";
            options.AppLabel = "triggergate";
            options.StorageDirectory = directory.Path;
            options.HttpPort = 9090;
            options.HttpsPort = tlsCa ? 9190 : 0;
            options.Version = "2.1.7";
            options.AdvertiseMdns = false;
            configure?.Invoke(options);
        }

        static Task SetLoopbackRemoteAddress(HttpContext context, RequestDelegate next)
        {
            context.Connection.RemoteIpAddress ??= IPAddress.Loopback;
            return next(context);
        }

        static Task RedirectEverything(HttpContext context)
        {
            context.Response.Redirect($"http://{context.Request.Host.Host}:8081{context.Request.Path}");
            return Task.CompletedTask;
        }
    }

    private static async Task<(int Status, string? Location, string Body, HttpResponseMessage Response)> Send(
        App app, HttpMethod method, string url, string? json = null, string? accept = null, string? fetchMode = null, string? fetchDest = null)
    {
        using HttpClient client = app.Web.GetTestClient();
        using HttpRequestMessage request = new(method, url);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        if (accept is not null)
        {
            _ = request.Headers.TryAddWithoutValidation("Accept", accept);
        }

        if (fetchMode is not null)
        {
            _ = request.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", fetchMode);
        }

        if (fetchDest is not null)
        {
            _ = request.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", fetchDest);
        }

        HttpResponseMessage response = await client.SendAsync(request);
        return ((int)response.StatusCode, response.Headers.Location?.OriginalString, await response.Content.ReadAsStringAsync(), response);
    }

    // The well-known paths win

    [TestMethod]
    [DataRow(AppPipeline.Fallback)]
    [DataRow(AppPipeline.RoutingFirst)]
    [DataRow(AppPipeline.RedirectEverything)]
    public async Task WellKnown_WinsOverTheAppsPipeline_OnEveryListener(AppPipeline pipeline)
    {
        await using App app = await Start(pipeline);
        foreach (string url in new[] { $"http://pi.local:9090{Prefix}/info.json", $"http://localhost:8081{Prefix}/info.json", $"https://pi.local:9190{Prefix}/info.json" })
        {
            (int status, string? location, string body, HttpResponseMessage response) = await Send(app, HttpMethod.Get, url);
            using (response)
            {
                Assert.AreEqual(200, status, url);
                Assert.IsNull(location, url);
                Assert.AreEqual("application/json", response.Content.Headers.ContentType?.MediaType, url);
                Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString(), url);
                Assert.AreEqual(9190, (int?)JsonNode.Parse(body)!["httpsPort"], url);
            }
        }

        (int pageStatus, _, string page, HttpResponseMessage pageResponse) = await Send(app, HttpMethod.Get, $"http://pi.local:9090{Prefix}/");
        using (pageResponse)
        {
            Assert.AreEqual(200, pageStatus);
            Assert.StartsWith("<!doctype html>", page);
        }
    }

    [TestMethod]
    [DataRow(AppPipeline.Fallback)]
    [DataRow(AppPipeline.RedirectEverything)]
    public async Task WellKnown_PostRenewIsServed_NotRedirected(AppPipeline pipeline)
    {
        await using App app = await Start(pipeline);
        (int status, string? location, string body, HttpResponseMessage response) = await Send(app, HttpMethod.Post, $"http://localhost:8081{Prefix}/renew", "{\"time\":1}");
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
            Assert.IsNotNull(JsonNode.Parse(body)!["caFingerprintSha256"]);
        }
    }

    [TestMethod]
    public async Task WellKnown_UnknownPathIs404_AndNeverReachesTheFallback()
    {
        await using App app = await Start();
        (int status, _, string body, HttpResponseMessage response) = await Send(app, HttpMethod.Get, $"http://pi.local:9090{Prefix}/unknown");
        using (response)
        {
            Assert.AreEqual(404, status);
            Assert.IsFalse(body.StartsWith("fallback ", StringComparison.Ordinal));
            Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        }
    }

    [TestMethod]
    [DataRow("/info.json", "GET, HEAD")]
    [DataRow("/", "GET, HEAD")]
    [DataRow("/renew", "POST")]
    public async Task WellKnown_WrongMethodIs405WithAllow(string path, string allow)
    {
        await using App app = await Start();
        HttpMethod method = allow == "POST" ? HttpMethod.Get : HttpMethod.Post;
        foreach (HttpMethod attempt in new[] { method, HttpMethod.Options, HttpMethod.Delete })
        {
            (int status, _, _, HttpResponseMessage response) = await Send(app, attempt, $"http://localhost:9090{Prefix}{path}", attempt == HttpMethod.Post ? "{}" : null);
            using (response)
            {
                Assert.AreEqual(405, status, $"{attempt} {path}");
                Assert.AreEqual(allow, string.Join(", ", response.Content.Headers.Allow), $"{attempt} {path}");
                Assert.IsFalse(response.Headers.Contains("Access-Control-Allow-Methods"));
            }
        }
    }

    [TestMethod]
    [DataRow("/.WELL-KNOWN/GameshowPro/INFO.JSON")]
    [DataRow("/.well-known/gameshowpro/info.json/")]
    [DataRow("/.well-known/gameshowpro")]
    public async Task WellKnown_CaseAndATrailingSlash_AreTolerated(string path)
    {
        await using App app = await Start();
        (int status, _, string body, HttpResponseMessage response) = await Send(app, HttpMethod.Get, "http://pi.local:9090" + path);
        using (response)
        {
            Assert.AreEqual(200, status, path);
            Assert.IsFalse(body.StartsWith("fallback ", StringComparison.Ordinal));
        }
    }

    [TestMethod]
    public async Task ALookalikePrefix_IsTheApps()
    {
        await using App app = await Start();
        (int status, _, string body, HttpResponseMessage response) = await Send(app, HttpMethod.Get, "http://pi.local:9090/.well-known/gameshowpro-other/info.json");
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.AreEqual("fallback GET /.well-known/gameshowpro-other/info.json", body);
        }
    }

    // The HTTP root redirect

    [TestMethod]
    [DataRow("GET", "http://pi.local:9090/?x=1&y=2", "http://pi.local:9090/.well-known/gameshowpro/?returnTo=%2F%3Fx%3D1%26y%3D2")]
    [DataRow("HEAD", "http://pi.local:9090/?x=1&y=2", "http://pi.local:9090/.well-known/gameshowpro/?returnTo=%2F%3Fx%3D1%26y%3D2")]
    [DataRow("GET", "http://studio-pc-triggergate.local:9090/", "http://studio-pc-triggergate.local:9090/.well-known/gameshowpro/?returnTo=%2F")]
    [DataRow("GET", "http://192.168.1.20:9090/", "http://192.168.1.20:9090/.well-known/gameshowpro/?returnTo=%2F")]
    [DataRow("HEAD", "http://[fe80::1]:9090/", "http://[fe80::1]:9090/.well-known/gameshowpro/?returnTo=%2F")]
    [DataRow("GET", "http://pi.local/", "http://pi.local/.well-known/gameshowpro/?returnTo=%2F")]
    [DataRow("GET", "http://127.0.0.2:9090/", "http://127.0.0.2:9090/.well-known/gameshowpro/?returnTo=%2F")]
    public async Task Root_NonLoopbackHostOverHttp_IsRedirectedToTheManagementPage(string method, string url, string expected)
    {
        await using App app = await Start();
        (int status, string? location, string body, HttpResponseMessage response) = await Send(app, new HttpMethod(method), url);
        using (response)
        {
            Assert.AreEqual(302, status, url);
            Assert.AreEqual(expected, location, url);
            Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString(), url);
            Assert.AreEqual("", body, url);
        }
    }

    [TestMethod]
    [DataRow("GET", "http://localhost:9090/?x=1")]
    [DataRow("HEAD", "http://localhost:9090/")]
    [DataRow("GET", "http://LOCALHOST:9090/")]
    [DataRow("GET", "http://127.0.0.1:9090/")]
    [DataRow("HEAD", "http://[::1]:9090/")]
    [DataRow("POST", "http://pi.local:9090/")]
    [DataRow("PUT", "http://pi.local:9090/")]
    [DataRow("GET", "http://pi.local:9090/settings")]
    [DataRow("GET", "http://pi.local:9090/index.html?x=1")]
    public async Task Root_LoopbackHostsHttpsOtherMethodsAndOtherPaths_ReachTheApp(string method, string url)
    {
        await using App app = await Start();
        (int status, string? location, string body, HttpResponseMessage response) = await Send(app, new HttpMethod(method), url, method is "POST" or "PUT" ? "{}" : null);
        using (response)
        {
            Assert.AreEqual(200, status, url);
            Assert.IsNull(location, url);
            if (method != "HEAD")
            {
                StringAssert.StartsWith(body, $"fallback {method} /", url);
            }
        }
    }

    [TestMethod]
    [DataRow("10.0.0.5", "http://10.0.0.5/.well-known/gameshowpro/?returnTo=%2F%3Fa%3Db")]
    [DataRow("fe80::1", "http://[fe80::1]/.well-known/gameshowpro/?returnTo=%2F%3Fa%3Db")]
    public async Task Root_WithoutAHost_UsesTheLocalAddress(string local, string expected)
    {
        await using App app = await Start();
        HttpContext context = await app.Web.GetTestServer().SendAsync(c => Prepare(c, IPAddress.Parse(local)));
        Assert.AreEqual(302, context.Response.StatusCode);
        Assert.AreEqual(expected, context.Response.Headers.Location.ToString());
        Assert.AreEqual("no-store", context.Response.Headers.CacheControl.ToString());
    }

    [TestMethod]
    public async Task Root_WithoutAHostOrALocalAddress_Is404()
    {
        await using App app = await Start();
        HttpContext context = await app.Web.GetTestServer().SendAsync(c => Prepare(c, null));
        Assert.AreEqual(404, context.Response.StatusCode);
    }

    [TestMethod]
    public async Task Root_WithoutAHostOnALoopbackAddress_ReachesTheApp()
    {
        await using App app = await Start();
        HttpContext context = await app.Web.GetTestServer().SendAsync(c => Prepare(c, IPAddress.Loopback));
        Assert.AreEqual(200, context.Response.StatusCode);
    }

    private static void Prepare(HttpContext context, IPAddress? local)
    {
        context.Request.Method = HttpMethods.Get;
        context.Request.Scheme = "http";
        context.Request.Host = default;
        context.Request.Path = "/";
        context.Request.QueryString = new QueryString("?a=b");
        context.Connection.LocalIpAddress = local;
    }

    [TestMethod]
    public async Task Root_RedirectCanBeTurnedOff()
    {
        await using App app = await Start(configure: options => options.RedirectHttpRoot = false);
        (int status, string? location, string body, HttpResponseMessage response) = await Send(app, HttpMethod.Get, "http://pi.local:9090/");
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
            Assert.AreEqual("fallback GET /", body);
        }
    }

    [TestMethod]
    [DataRow("GET", "/settings?tab=network", "text/html", null, null)]
    [DataRow("HEAD", "/dashboard?x=1", null, "navigate", "document")]
    [DataRow("GET", "/frame?x=1", null, "navigate", "iframe")]
    public async Task HttpPageNavigation_ReachesManagementWithOriginalPath(string method, string path, string? accept, string? fetchMode, string? fetchDest)
    {
        await using App app = await Start();
        (int status, string? location, _, HttpResponseMessage response) = await Send(
            app, new HttpMethod(method), "http://pi.local:9090" + path, accept: accept, fetchMode: fetchMode, fetchDest: fetchDest);
        using (response)
        {
            Assert.AreEqual(302, status);
            Assert.AreEqual($"http://pi.local:9090{Prefix}/?returnTo={Uri.EscapeDataString(path)}", location);
            Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        }
    }

    [TestMethod]
    [DataRow("GET", "/api/data", "application/json", null, null)]
    [DataRow("GET", "/api/data", "text/html", "cors", "empty")]
    [DataRow("GET", "/api/data", "application/x-text/html", null, null)]
    [DataRow("GET", "/api/data", "text/html;q=0", null, null)]
    [DataRow("GET", "/api/data", "%%%", null, null)]
    [DataRow("GET", "/", "application/json", null, null)]
    [DataRow("GET", "/", "text/html", "same-origin", "empty")]
    [DataRow("POST", "/", "text/html", "navigate", "document")]
    public async Task HttpNonNavigation_ReachesApp(string method, string path, string? accept, string? fetchMode, string? fetchDest)
    {
        await using App app = await Start();
        (int status, string? location, string body, HttpResponseMessage response) = await Send(
            app, new HttpMethod(method), "http://pi.local:9090" + path,
            method == "POST" ? "{}" : null, accept, fetchMode, fetchDest);
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
            StringAssert.StartsWith(body, $"fallback {method} {path}");
        }
    }

    [TestMethod]
    public async Task HttpsWrongHost_PageNavigationGoesThroughSameHostManagementPage()
    {
        await using App app = await Start();
        (int status, string? location, _, HttpResponseMessage response) = await Send(
            app, HttpMethod.Get, "https://192.168.1.20:9190/settings?q=1", accept: "text/html");
        using (response)
        {
            Assert.AreEqual(302, status);
            Assert.AreEqual($"https://192.168.1.20:9190{Prefix}/?returnTo=%2Fsettings%3Fq%3D1", location);
        }

        string canonical = app.Web.Services.GetRequiredService<ITlsCaStatus>().MdnsName;
        (status, location, _, response) = await Send(app, HttpMethod.Get, $"https://{canonical}:9190/settings?q=1", accept: "text/html");
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
        }
    }

    [TestMethod]
    [DataRow("GET", "application/json")]
    [DataRow("POST", "text/html")]
    public async Task HttpsWrongHost_NonNavigationReachesApp(string method, string accept)
    {
        await using App app = await Start();
        (int status, string? location, _, HttpResponseMessage response) = await Send(
            app, new HttpMethod(method), "https://192.168.1.20:9190/api", method == "POST" ? "{}" : null, accept);
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
        }
    }

    [TestMethod]
    [DataRow("http://pi.local:9090/settings")]
    [DataRow("https://pi.local:9190/settings")]
    public async Task BuiltInFallbackCookie_SuppressesRedirectUnlessOptionIsOff(string url)
    {
        await using App app = await Start();
        using HttpClient client = app.Web.GetTestClient();
        using HttpRequestMessage request = new(HttpMethod.Get, url);
        _ = request.Headers.TryAddWithoutValidation("Accept", "text/html");
        _ = request.Headers.TryAddWithoutValidation("Cookie", "gsp-tlsca-http=1");
        using HttpResponseMessage response = await client.SendAsync(request);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);

        await using App disabled = await Start(configure: options => options.AllowHttpFallback = false);
        using HttpClient disabledClient = disabled.Web.GetTestClient();
        using HttpRequestMessage disabledRequest = new(HttpMethod.Get, url);
        _ = disabledRequest.Headers.TryAddWithoutValidation("Accept", "text/html");
        _ = disabledRequest.Headers.TryAddWithoutValidation("Cookie", "gsp-tlsca-http=1");
        using HttpResponseMessage redirected = await disabledClient.SendAsync(disabledRequest);
        Assert.AreEqual(HttpStatusCode.Found, redirected.StatusCode);
    }

    [TestMethod]
    [DataRow("renew")]
    [DataRow("reset")]
    public async Task BuiltInFallbackCookie_DoesNotBypassManagementGate(string action)
    {
        await using App app = await Start();
        using HttpClient client = app.Web.GetTestClient();
        using HttpRequestMessage request = new(HttpMethod.Post, $"http://pi.local:9090{Prefix}/{action}")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        _ = request.Headers.TryAddWithoutValidation("Cookie", "gsp-tlsca-http=1");
        using HttpResponseMessage response = await client.SendAsync(request);
        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [TestMethod]
    [DataRow("http://localhost:9090/settings")]
    [DataRow("https://localhost:9190/settings")]
    public async Task LocalhostBrowserNavigation_ReachesApp(string url)
    {
        await using App app = await Start();
        (int status, string? location, _, HttpResponseMessage response) = await Send(app, HttpMethod.Get, url, accept: "text/html");
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
        }
    }

    [TestMethod]
    [DataRow("//evil.example/path")]
    [DataRow("/\\evil.example/path")]
    [DataRow("/%2F%2Fevil.example/path")]
    public async Task UnsafePath_IsNotCarriedInRedirect(string path)
    {
        await using App app = await Start();
        HttpContext context = await app.Web.GetTestServer().SendAsync(PrepareUnsafePath);
        Assert.AreEqual(200, context.Response.StatusCode);
        Assert.IsFalse(context.Response.Headers.ContainsKey("Location"));

        void PrepareUnsafePath(HttpContext context)
        {
            context.Request.Method = HttpMethods.Get;
            context.Request.Scheme = "http";
            context.Request.Host = new HostString("pi.local", 9090);
            context.Request.Path = new PathString(path);
            context.Request.Headers.Accept = "text/html";
        }
    }

    [TestMethod]
    public async Task RedirectOptions_AreIndependent()
    {
        await using App app = await Start(configure: ConfigureRedirects);
        (int status, _, _, HttpResponseMessage root) = await Send(app, HttpMethod.Get, "http://pi.local:9090/");
        using (root)
        {
            Assert.AreEqual(302, status, "The existing root option stays enabled.");
        }

        (status, _, _, HttpResponseMessage other) = await Send(app, HttpMethod.Get, "http://pi.local:9090/settings", accept: "text/html");
        using (other)
        {
            Assert.AreEqual(200, status);
        }

        (status, _, _, HttpResponseMessage secure) = await Send(app, HttpMethod.Get, "https://pi.local:9190/settings", accept: "text/html");
        using (secure)
        {
            Assert.AreEqual(200, status);
        }

        static void ConfigureRedirects(TlsCaOptions options)
        {
            options.RedirectHttpNavigations = false;
            options.RedirectHttpsHost = false;
        }
    }

    [TestMethod]
    public async Task OwnCertificate_HttpNavigationRedirectsOnlyMatchingDnsHost()
    {
        using TestChain chain = TestChain.Create(withIntermediate: false);
        using TempDirectory files = new();
        string pfx = chain.WritePfx(files.Path, "redirect-test");
        await using App app = await Start(configure: ConfigureOwn, expectedMode: TlsCaMode.OwnCertificate);

        (int status, string? location, _, HttpResponseMessage matching) = await Send(
            app, HttpMethod.Get, "http://server.example.test:9090/settings?q=1", accept: "text/html");
        using (matching)
        {
            Assert.AreEqual(302, status);
            Assert.AreEqual("https://server.example.test:9190/settings?q=1", location);
        }

        foreach (string url in new[] { "http://other.example.test:9090/settings", "http://localhost:9090/settings", "http://server.example.test:9090/api" })
        {
            (status, location, _, HttpResponseMessage ignored) = await Send(app, HttpMethod.Get, url, accept: url.EndsWith("/api", StringComparison.Ordinal) ? "application/json" : "text/html");
            using (ignored)
            {
                Assert.AreEqual(200, status, url);
                Assert.IsNull(location, url);
            }
        }

        (status, location, _, HttpResponseMessage post) = await Send(
            app, HttpMethod.Post, "http://server.example.test:9090/settings", json: "{}", accept: "text/html");
        using (post)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
        }

        await using App disabled = await Start(configure: ConfigureDisabledOwn, expectedMode: TlsCaMode.OwnCertificate);
        (status, location, _, HttpResponseMessage disabledResponse) = await Send(
            disabled, HttpMethod.Get, "http://server.example.test:9090/settings", accept: "text/html");
        using (disabledResponse)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
        }

        void ConfigureOwn(TlsCaOptions options)
        {
            options.CertificatePath = pfx;
            options.CertificatePassword = "redirect-test";
        }

        void ConfigureDisabledOwn(TlsCaOptions options)
        {
            ConfigureOwn(options);
            options.RedirectOwnCertificateHttp = false;
        }
    }

    [TestMethod]
    [DataRow(TlsCaMode.Off)]
    [DataRow(TlsCaMode.KestrelCertificate)]
    public async Task ModesWithoutLibraryCertificate_DoNotRedirect(TlsCaMode mode)
    {
        await using App app = await Start(tlsCa: mode != TlsCaMode.Off, expectedMode: mode);
        (int status, string? location, _, HttpResponseMessage response) = await Send(
            app, HttpMethod.Get, "http://pi.local:9090/settings", accept: "text/html");
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
        }
    }

    // Without the CA

    [TestMethod]
    public async Task HttpsOff_TheRootIsNotRedirected_ButThePrefixIsStillServed()
    {
        await using App app = await Start(tlsCa: false);

        (int status, string? location, string body, HttpResponseMessage response) = await Send(app, HttpMethod.Get, "http://pi.local:9090/");
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.IsNull(location);
            Assert.AreEqual("fallback GET /", body);
        }

        (status, location, body, response) = await Send(app, HttpMethod.Get, $"http://pi.local:9090{Prefix}/info.json");
        using (response)
        {
            Assert.AreEqual(200, status);
            Assert.AreEqual("off", (string?)JsonNode.Parse(body)!["certificateSource"]);
        }
    }

    [TestMethod]
    public async Task WithoutAdd_UseAndMapThrow()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.WebHost.UseTestServer();
        await using WebApplication app = builder.Build();
        _ = Assert.ThrowsExactly<InvalidOperationException>(app.MapGameshowProTlsCa);
        _ = Assert.ThrowsExactly<InvalidOperationException>(app.UseGameshowProTlsCa);
    }

    // Helpers

    [TestMethod]
    [DataRow("/.well-known/gameshowpro", true)]
    [DataRow("/.well-known/gameshowpro/", true)]
    [DataRow("/.well-known/gameshowpro/info.json", true)]
    [DataRow("/.WELL-KNOWN/GAMESHOWPRO/ca.crt", true)]
    [DataRow("/.well-known/gameshowpro-other", false)]
    [DataRow("/.well-known", false)]
    [DataRow("/", false)]
    [DataRow("/x/.well-known/gameshowpro", false)]
    public void IsWellKnown_IsThePrefixAndBelowOnly(string path, bool expected) =>
        Assert.AreEqual(expected, TlsCaPaths.IsWellKnown(new PathString(path)));

    [TestMethod]
    [DataRow("localhost", true)]
    [DataRow("LocalHost:9090", true)]
    [DataRow("127.0.0.1", true)]
    [DataRow("127.0.0.1:19090", true)]
    [DataRow("[::1]", true)]
    [DataRow("[::1]:9090", true)]
    [DataRow("pi.local:9090", false)]
    [DataRow("127.0.0.2", false)]
    [DataRow("localhost.evil.example", false)]
    [DataRow("", false)]
    public void IsLoopbackHost_IsTheThreeLiteralsWithAnyPort(string host, bool expected) =>
        Assert.AreEqual(expected, LoopbackGate.IsLoopbackHost(new HostString(host)));
}
