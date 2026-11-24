namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// <c>UseGameshowProTlsCa</c> in front of an app's own pipeline: the well-known paths win over the app's routing,
/// fallback and redirects, and the plain-HTTP root of a non-loopback host is redirected to the management page.
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

    private static async Task<App> Start(AppPipeline pipeline = AppPipeline.Fallback, Action<TlsCaOptions>? configure = null, bool tlsCa = true)
    {
        TempDirectory directory = new();
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.Logging.ClearProviders();
        _ = builder.WebHost.UseTestServer();
        TlsCaMode mode = builder.AddGameshowProTlsCa(ConfigureOptions);
        Assert.AreEqual(tlsCa ? TlsCaMode.BuiltInCa : TlsCaMode.Off, mode);
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

    private static async Task<(int Status, string? Location, string Body, HttpResponseMessage Response)> Send(App app, HttpMethod method, string url, string? json = null)
    {
        using HttpClient client = app.Web.GetTestClient();
        using HttpRequestMessage request = new(method, url);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
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
            Assert.DoesNotContain("fallback", body);
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
            Assert.DoesNotContain("fallback", body);
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
    [DataRow("GET", "http://pi.local:9090/?x=1&y=2", "http://pi.local:9090/.well-known/gameshowpro/?x=1&y=2")]
    [DataRow("HEAD", "http://pi.local:9090/?x=1&y=2", "http://pi.local:9090/.well-known/gameshowpro/?x=1&y=2")]
    [DataRow("GET", "http://studio-pc-triggergate.local:9090/", "http://studio-pc-triggergate.local:9090/.well-known/gameshowpro/")]
    [DataRow("GET", "http://192.168.1.20:9090/", "http://192.168.1.20:9090/.well-known/gameshowpro/")]
    [DataRow("HEAD", "http://[fe80::1]:9090/", "http://[fe80::1]:9090/.well-known/gameshowpro/")]
    [DataRow("GET", "http://pi.local/", "http://pi.local/.well-known/gameshowpro/")]
    [DataRow("GET", "http://127.0.0.2:9090/", "http://127.0.0.2:9090/.well-known/gameshowpro/")]
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
    [DataRow("GET", "https://pi.local:9190/")]
    [DataRow("HEAD", "https://192.168.1.20:9190/")]
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
    [DataRow("10.0.0.5", "http://10.0.0.5/.well-known/gameshowpro/?a=b")]
    [DataRow("fe80::1", "http://[fe80::1]/.well-known/gameshowpro/?a=b")]
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
