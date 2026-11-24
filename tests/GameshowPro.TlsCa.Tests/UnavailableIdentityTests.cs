namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// The ASP.NET Core integration when no identity can be loaded or created: the app starts, <see cref="ITlsCaStatus"/>
/// reports the problem, the certificate endpoints answer 503, the page is served, and a gated reset (from the machine
/// itself only) recovers without a restart. The real HTTPS listener is covered by <see cref="KestrelIntegrationTests"/>.
/// </summary>
[TestClass]
public sealed class UnavailableIdentityTests
{
    private const string Prefix = "/.well-known/gameshowpro";

    private static Task<TestApp> StartCorrupt(Action<TlsCaOptions>? configure = null, TestLogProvider? logs = null) =>
        TestApp.Start(configure, logs, path => _ = BrokenStorage.WriteCorruptIdentity(path));

    [TestMethod]
    public async Task CorruptIdentity_AppStarts_AndTheStatusReportsTheProblem()
    {
        TestLogProvider logs = new();
        await using TestApp app = await StartCorrupt(logs: logs);
        ITlsCaStatus status = app.Status;

        Assert.IsFalse(app.Manager.IsLoaded);
        Assert.IsNotNull(status.IdentityProblem);
        Assert.Contains("corrupt", status.IdentityProblem);
        Assert.AreEqual("", status.MdnsName);
        Assert.AreEqual("", status.CaFingerprintSha256);
        Assert.IsNull(status.NameMismatch);
        Assert.IsFalse(status.NameConflict);
        Assert.AreEqual(9443, status.HttpsPort);

        // One error (the reason) and one warning (what to do), at startup.
        Assert.HasCount(1, logs.AtLeast(LogLevel.Error), string.Join(Environment.NewLine, logs.Messages));
        Assert.IsTrue(logs.Messages.Any(message => message.StartsWith("Warning: Running without a TLS identity", StringComparison.Ordinal)), string.Join(Environment.NewLine, logs.Messages));
    }

    [TestMethod]
    public async Task CorruptIdentity_PageIsServed_AndTheCertificateEndpointsAnswer503()
    {
        byte[]? corrupt = null;
        await using TestApp app = await TestApp.Start(prepareStorage: path => corrupt = BrokenStorage.WriteCorruptIdentity(path));

        using HttpResponseMessage page = await app.Get(Prefix + "/");
        Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
        Assert.AreEqual("text/html", page.Content.Headers.ContentType?.MediaType);
        Assert.AreEqual("no-store", page.Headers.CacheControl?.ToString());

        foreach (string path in new[] { "/ca.crt", "/ca.pem", "/ca.mobileconfig" })
        {
            using HttpResponseMessage response = await app.Get(Prefix + path);
            Assert.AreEqual(HttpStatusCode.ServiceUnavailable, response.StatusCode, path);
            Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString(), path);
            Assert.AreEqual("text/plain", response.Content.Headers.ContentType?.MediaType, path);
            Assert.Contains("reset", await response.Content.ReadAsStringAsync(), path);
        }

        using HttpResponseMessage head = await app.Send(HttpMethod.Head, Prefix + "/info.json");
        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, head.StatusCode);
        Assert.AreEqual("no-store", head.Headers.CacheControl?.ToString());

        // The file is left exactly as it was: a new identity is only ever created by an explicit reset.
        CollectionAssert.AreEqual(corrupt, File.ReadAllBytes(Path.Combine(app.StorageDirectory, FileIdentityStore.FileName)));
    }

    [TestMethod]
    public async Task CorruptIdentity_InfoJsonIs503_WithAJsonBodyThePageUnderstands()
    {
        await using TestApp app = await StartCorrupt();

        using HttpResponseMessage response = await app.Get(Prefix + "/info.json");

        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        Assert.AreEqual("application/json", response.Content.Headers.ContentType?.MediaType);
        JsonObject body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.AreEqual(true, (bool?)body["identityUnavailable"]);
        Assert.IsFalse(string.IsNullOrWhiteSpace((string?)body["error"]));
        Assert.AreEqual("TriggerGate", (string?)body["product"]);
        Assert.AreEqual("loopback", (string?)body["gate"]);
        Assert.AreEqual(9443, (int?)body["httpsPort"]);
        Assert.AreEqual("2.1.7", (string?)body["version"]);
        // The reason names local paths; it is only in the log and ITlsCaStatus.
        Assert.DoesNotContain(app.StorageDirectory, body.ToJsonString(), StringComparison.OrdinalIgnoreCase);
    }

    [TestMethod]
    public async Task CorruptIdentity_RenewIs503_WithAJsonError()
    {
        await using TestApp app = await StartCorrupt();

        using HttpResponseMessage response = await app.PostJson(Prefix + "/renew");

        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        Assert.AreEqual("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.IsFalse(string.IsNullOrWhiteSpace((string?)JsonNode.Parse(await response.Content.ReadAsStringAsync())!["error"]));
        Assert.IsFalse(app.Manager.IsLoaded);
    }

    [TestMethod]
    public async Task CorruptIdentity_PostsKeepTheirMethodAndContentTypeRules()
    {
        await using TestApp app = await StartCorrupt();

        using HttpResponseMessage get = await app.Get(Prefix + "/reset");
        using HttpResponseMessage text = await app.Send(HttpMethod.Post, Prefix + "/reset", request => request.Content = new StringContent("{}", Encoding.UTF8, "text/plain"));

        Assert.AreEqual(HttpStatusCode.MethodNotAllowed, get.StatusCode);
        Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, text.StatusCode);
        Assert.IsFalse(app.Manager.IsLoaded);
    }

    [TestMethod]
    [DataRow("localhost")]
    [DataRow("localhost:9090")]
    [DataRow("127.0.0.1:9090")]
    [DataRow("[::1]:9090")]
    public async Task CorruptIdentity_ResetFromTheMachine_RecoversWithoutARestart_AndRaisesChanged(string host)
    {
        await using TestApp app = await StartCorrupt();
        ITlsCaStatus status = app.Status;
        int changed = 0;
        string? problemSeenByHandler = "not called";
        status.Changed += ObserveChanged;

        void ObserveChanged(object? sender, EventArgs args)
        {
            changed++;
            problemSeenByHandler = status.IdentityProblem;
        }

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset", request => request.Headers.Host = host);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        TlsIdentity identity = app.Manager.Current;
        Assert.AreEqual(identity.CaFingerprintSha256, (string?)info["caFingerprintSha256"]);
        // The corrupt file's CA cannot be read, so there is no previous fingerprint to record.
        Assert.IsNull(info["previousCaFingerprintSha256"]);

        Assert.AreEqual(1, changed);
        Assert.IsNull(problemSeenByHandler);
        Assert.IsNull(status.IdentityProblem);
        Assert.AreEqual(identity.MdnsName, status.MdnsName);
        Assert.AreEqual(identity.CaFingerprintSha256, status.CaFingerprintSha256);
        Assert.IsNull(status.NameMismatch);

        // Every endpoint works again.
        foreach (string path in new[] { "/ca.crt", "/ca.pem", "/ca.mobileconfig", "/info.json" })
        {
            using HttpResponseMessage after = await app.Get(Prefix + path);
            Assert.AreEqual(HttpStatusCode.OK, after.StatusCode, path);
        }

        Assert.AreEqual(identity.CaFingerprintSha256, Fingerprint.Sha256(await app.Client.GetByteArrayAsync(Prefix + "/ca.crt")));
        using StoredIdentity stored = app.LoadStored();
        Assert.AreEqual(identity.CaFingerprintSha256, Fingerprint.Sha256(stored.CaCertificateDer));
    }

    [TestMethod]
    [DataRow("192.168.1.50")]
    [DataRow("2001:db8::1")]
    [DataRow("::ffff:192.168.1.50")]
    [DataRow("none")]
    public async Task CorruptIdentity_ResetFromANonLoopbackRemote_Is403_AndChangesNothing(string remote)
    {
        byte[]? corrupt = null;
        await using TestApp app = await TestApp.Start(prepareStorage: path => corrupt = BrokenStorage.WriteCorruptIdentity(path));

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset", AddForwardedRemote);

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        Assert.IsFalse(app.Manager.IsLoaded);
        Assert.IsNotNull(app.Status.IdentityProblem);
        CollectionAssert.AreEqual(corrupt, File.ReadAllBytes(Path.Combine(app.StorageDirectory, FileIdentityStore.FileName)));

        void AddForwardedRemote(HttpRequestMessage request)
        {
            request.Headers.Add(TestApp.RemoteHeader, remote);
            request.Headers.Add("X-Forwarded-For", "127.0.0.1");
        }
    }

    /// <summary>With no identity there is no device name, so only <c>localhost</c> and loopback literals are the machine.</summary>
    [TestMethod]
    [DataRow("{derived}.local", null)]
    [DataRow("{derived}.local:9090", null)]
    [DataRow("evil.example", null)]
    [DataRow("192.168.1.10:9090", null)]
    [DataRow("localhost:9090", "http://evil.example")]
    [DataRow("localhost:9090", "http://localhost:1234")]
    [DataRow("localhost:9090", "null")]
    public async Task CorruptIdentity_ResetWithAForeignHostOrOrigin_Is403(string host, string? origin)
    {
        await using TestApp app = await StartCorrupt();
        string derived = DeviceName.Derive(Environment.MachineName, TestManagers.AppLabel);

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset", SetForeignHostOrOrigin);

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.IsFalse(app.Manager.IsLoaded);

        void SetForeignHostOrOrigin(HttpRequestMessage request)
        {
            request.Headers.Host = host.Replace("{derived}", derived, StringComparison.Ordinal);
            if (origin is not null)
            {
                _ = request.Headers.TryAddWithoutValidation("Origin", origin);
            }
        }
    }

    [TestMethod]
    public async Task CorruptIdentity_ResetWithAnOriginEqualToTheHost_IsAllowed()
    {
        await using TestApp app = await StartCorrupt();

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset", SetMatchingOrigin);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.IsTrue(app.Manager.IsLoaded);

        static void SetMatchingOrigin(HttpRequestMessage request)
        {
            request.Headers.Host = "localhost:9090";
            _ = request.Headers.TryAddWithoutValidation("Origin", "http://localhost:9090");
        }
    }

    [TestMethod]
    public async Task UnwritableStorage_AppStarts_AndAResetThatCannotSaveIs500_AndLeavesTheModeInForce()
    {
        string? storage = null;
        await using TestApp app = await TestApp.Start(
            options => options.StorageDirectory = storage!,
            prepareStorage: path => storage = BrokenStorage.Unwritable(path));
        ITlsCaStatus status = app.Status;
        int changed = 0;
        status.Changed += (_, _) => changed++;

        Assert.IsNotNull(status.IdentityProblem);
        Assert.Contains("could not be written", status.IdentityProblem);

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset");

        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        Assert.IsFalse(string.IsNullOrWhiteSpace((string?)JsonNode.Parse(await response.Content.ReadAsStringAsync())!["error"]));
        Assert.IsFalse(app.Manager.IsLoaded);
        Assert.IsNotNull(status.IdentityProblem);
        Assert.AreEqual("", status.MdnsName);
        Assert.AreEqual(0, changed);
        using HttpResponseMessage info = await app.Get(Prefix + "/info.json");
        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, info.StatusCode);
    }

    [TestMethod]
    public async Task CustomGate_WithoutTheNewMember_RefusesAResetWithoutIdentity()
    {
        await using TestApp app = await StartCorrupt(options => options.Gate = new IdentityOnlyGate());

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset");

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.IsFalse(app.Manager.IsLoaded);
    }

    [TestMethod]
    public async Task CustomGate_ThatAllowsWithoutIdentity_CanReset()
    {
        await using TestApp app = await StartCorrupt(options => options.Gate = new ButtonGate());

        using HttpResponseMessage info = await app.Get(Prefix + "/info.json");
        Assert.AreEqual("button", (string?)JsonNode.Parse(await info.Content.ReadAsStringAsync())!["gate"]);
        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset", request => request.Headers.Add(TestApp.RemoteHeader, "192.168.1.50"));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.IsTrue(app.Manager.IsLoaded);
    }

    [TestMethod]
    public async Task NoResponse_WhileUnavailable_ContainsTheReason()
    {
        await using TestApp app = await StartCorrupt();
        string problem = app.Status.IdentityProblem!;

        foreach (string path in new[] { "/info.json", "/ca.crt", "/ca.pem", "/ca.mobileconfig" })
        {
            using HttpResponseMessage response = await app.Get(Prefix + path);
            string body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain(problem, body, path);
            Assert.DoesNotContain(FileIdentityStore.FileName, body, path);
        }
    }

    // The gate on its own

    [TestMethod]
    [DataRow("127.0.0.1", "localhost", true)]
    [DataRow("127.0.0.1", "127.0.0.1:9090", true)]
    [DataRow("::1", "[::1]:9090", true)]
    [DataRow("127.0.0.1", "127.0.0.2", true)]
    [DataRow("127.0.0.1", "studio-pc-triggergate.local", false)]
    [DataRow("127.0.0.1", "evil.example", false)]
    [DataRow("192.168.1.50", "localhost", false)]
    public async Task LoopbackGate_WithoutIdentity_AcceptsOnlyLoopbackNames(string remote, string host, bool expected)
    {
        DefaultHttpContext context = new();
        context.Connection.RemoteIpAddress = IPAddress.Parse(remote);
        context.Request.Host = new HostString(host);

        Assert.AreEqual(expected, await new LoopbackGate().IsAllowedWithoutIdentity(context));
    }

    // The hosted services

    /// <summary>
    /// Nothing is advertised while there is no identity; after a reset the service goes on to advertise. The HTTPS port is
    /// out of range for mDNS here, so the attempt fails before any socket is opened, which proves the attempt was made
    /// without announcing anything on the test machine's network.
    /// </summary>
    [TestMethod]
    public async Task MdnsService_AdvertisesNothingWithoutIdentity_AndStartsAfterAReset()
    {
        using TempDirectory directory = new();
        _ = BrokenStorage.WriteCorruptIdentity(directory.Path);
        TestLogProvider logs = new();
        using ILoggerFactory loggers = LoggerFactory.Create(builder => builder.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
        using TlsIdentityManager manager = TestManagers.Create(directory.CreateStore(), TimeProvider.System);
        _ = await Assert.ThrowsAsync<IdentityStoreException>(async () => await manager.LoadOrCreate());
        TlsCaOptions options = TestManagers.Options(o => (o.HttpPort, o.HttpsPort) = (0, 70000));
        using TlsCaStatus status = new(manager, options, loggers.CreateLogger<TlsCaStatus>());
        using TlsCaMdnsService service = new(manager, options, status, TimeProvider.System, loggers.CreateLogger<TlsCaMdnsService>());

        await service.StartAsync(CancellationToken.None);
        try
        {
            await WaitFor(() => logs.Messages.Any(message => message.Contains("Not advertising over mDNS", StringComparison.Ordinal)), logs);
            await Task.Delay(TlsCaMdnsService.CheckInterval + TimeSpan.FromMilliseconds(500));
            Assert.IsFalse(logs.Messages.Any(message => message.Contains("mDNS advertisement failed", StringComparison.Ordinal) || message.Contains("Advertising", StringComparison.Ordinal)), string.Join(Environment.NewLine, logs.Messages));

            _ = await manager.ResetIdentity();

            await WaitFor(() => logs.Messages.Any(message => message.Contains("mDNS advertisement failed", StringComparison.Ordinal)), logs);
            Assert.IsFalse(status.NameConflict);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }

    private static async Task WaitFor(Func<bool> condition, TestLogProvider logs)
    {
        for (int i = 0; i < 200 && !condition(); i++)
        {
            await Task.Delay(50);
        }

        Assert.IsTrue(condition(), string.Join(Environment.NewLine, logs.Messages));
    }

    // The pipeline

    [TestMethod]
    public async Task CorruptIdentity_TheHttpRootRedirectIsUnchanged()
    {
        using TempDirectory directory = new();
        _ = BrokenStorage.WriteCorruptIdentity(directory.Path);
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.Logging.ClearProviders();
        _ = builder.WebHost.UseTestServer();
        Assert.AreEqual(TlsCaMode.BuiltInCa, builder.AddGameshowProTlsCa(options =>
        {
            options.Product = "TriggerGate";
            options.AppLabel = "triggergate";
            options.StorageDirectory = directory.Path;
            options.HttpPort = 9090;
            options.HttpsPort = 9190;
            options.AdvertiseMdns = false;
        }));
        await using WebApplication app = builder.Build();
        _ = app.UseGameshowProTlsCa();
        _ = app.MapFallback("{**path}", context => context.Response.WriteAsync("fallback"));
        await app.StartAsync();
        try
        {
            using HttpClient client = app.GetTestClient();
            using HttpResponseMessage redirected = await client.GetAsync("http://pi.local:9090/?x=1");
            using HttpResponseMessage local = await client.GetAsync("http://localhost:9090/");
            using HttpResponseMessage page = await client.GetAsync($"http://pi.local:9090{Prefix}/");

            Assert.AreEqual(HttpStatusCode.Found, redirected.StatusCode);
            Assert.AreEqual($"http://pi.local:9090{Prefix}/?returnTo=%2F%3Fx%3D1", redirected.Headers.Location?.OriginalString);
            Assert.AreEqual("fallback", await local.Content.ReadAsStringAsync());
            Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
            Assert.IsNotNull(app.Services.GetRequiredService<ITlsCaStatus>().IdentityProblem);
        }
        finally
        {
            await app.StopAsync();
        }
    }

    /// <summary>A gate written before <see cref="ITlsCaGate.IsAllowedWithoutIdentity"/> existed: it allows everything it is asked.</summary>
    private sealed class IdentityOnlyGate : ITlsCaGate
    {
        public string Kind => "custom";

        public ValueTask<bool> IsAllowed(HttpContext context, TlsIdentity identity) => ValueTask.FromResult(true);
    }

    /// <summary>A presence gate that needs no identity, like a hardware button that was pressed.</summary>
    private sealed class ButtonGate : ITlsCaGate
    {
        public string Kind => "button";

        public ValueTask<bool> IsAllowed(HttpContext context, TlsIdentity identity) => ValueTask.FromResult(true);

        public ValueTask<bool> IsAllowedWithoutIdentity(HttpContext context) => ValueTask.FromResult(true);
    }
}
