namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Real Kestrel on loopback with ephemeral ports: the app declares its HTTP port the way TriggerGate does
/// (<c>UseUrls</c>) and <c>AddGameshowProTlsCa</c> must add HTTPS without cancelling it.
/// </summary>
[TestClass]
[DoNotParallelize]
public sealed class KestrelIntegrationTests
{
    [TestMethod]
    public async Task UseUrlsHttpPort_AndHttpsPort_AreBothListening_AndTheCaTrustedClientReachesInfoOverHttps()
    {
        int httpPort = TestPorts.Reserve();
        int httpsPort = TestPorts.Reserve();
        TestLogProvider logs = new();
        await using RunningApp app = await RunningApp.Start(
            builder => builder.WebHost.UseUrls($"http://127.0.0.1:{httpPort}"),
            options => (options.HttpPort, options.HttpsPort) = (httpPort, httpsPort),
            logs);

        // Plain HTTP, declared by the app through UseUrls, is still bound.
        using HttpClient plain = new();
        string infoText = await plain.GetStringAsync($"http://127.0.0.1:{httpPort}/.well-known/gameshowpro/info.json");
        JsonObject info = JsonNode.Parse(infoText)!.AsObject();
        string name = (string)info["name"]!;
        Assert.AreEqual(httpsPort, (int?)info["httpsPort"]);
        byte[] caDer = await plain.GetByteArrayAsync($"http://127.0.0.1:{httpPort}/.well-known/gameshowpro/ca.crt");
        Assert.AreEqual((string?)info["caFingerprintSha256"], Fingerprint.Sha256(caDer));

        // HTTPS: trusts only the CA, connects to the loopback address but validates the name <name>.local.
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(caDer);
        using HttpClient secure = CreateClientTrusting(ca);
        string secureText = await secure.GetStringAsync($"https://{name}.local:{httpsPort}/.well-known/gameshowpro/info.json");
        Assert.AreEqual((string?)info["caFingerprintSha256"], (string?)JsonNode.Parse(secureText)!["caFingerprintSha256"]);

        // The same request without the CA in the trust store is refused, so the test is not passing vacuously.
        using SocketsHttpHandler untrusting = new() { ConnectCallback = ConnectToLoopback };
        using HttpClient defaultTrust = new(untrusting);
        _ = await Assert.ThrowsAsync<HttpRequestException>(() => defaultTrust.GetStringAsync($"https://{name}.local:{httpsPort}/.well-known/gameshowpro/info.json"));

        // A wrong name is refused even by a client that trusts the CA: the leaf is for <name>.local only.
        using HttpClient wrongName = CreateClientTrusting(ca);
        _ = await Assert.ThrowsAsync<HttpRequestException>(() => wrongName.GetStringAsync($"https://other-name.local:{httpsPort}/.well-known/gameshowpro/info.json"));

        // The renewed leaf is served to the next connection without restarting the listener.
        string before = app.Manager.Current.LeafFingerprintSha256;
        using HttpResponseMessage renew = await plain.PostAsync(
            $"http://127.0.0.1:{httpPort}/.well-known/gameshowpro/renew",
            new StringContent("{\"time\":1}", Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.OK, renew.StatusCode);
        Assert.AreNotEqual(before, app.Manager.Current.LeafFingerprintSha256);
        using HttpClient afterRenew = CreateClientTrusting(ca);
        _ = await afterRenew.GetStringAsync($"https://{name}.local:{httpsPort}/.well-known/gameshowpro/info.json");

        // Evidence of how Kestrel treated the URLs (also printed by the test run).
        Console.WriteLine(string.Join(Environment.NewLine, logs.Messages));
        Assert.IsTrue(logs.Messages.Any(message => message.Contains(httpsPort.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)), "Kestrel did not report the HTTPS port.");
    }

    [TestMethod]
    [DoNotParallelize]
    public async Task AspNetCoreUrlsEnvironmentVariable_IsAlsoKept()
    {
        int httpPort = TestPorts.Reserve();
        int httpsPort = TestPorts.Reserve();
        string? original = Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", $"http://127.0.0.1:{httpPort}");
        try
        {
            await using RunningApp app = await RunningApp.Start(
                _ => { },
                options => (options.HttpPort, options.HttpsPort) = (0, httpsPort),
                new TestLogProvider());

            using HttpClient plain = new();
            using HttpResponseMessage response = await plain.GetAsync($"http://127.0.0.1:{httpPort}/.well-known/gameshowpro/info.json");
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_URLS", original);
        }
    }

    [TestMethod]
    [DoNotParallelize]
    public async Task NoDeclaredUrls_BindsTheConfiguredHttpPort()
    {
        int httpPort = TestPorts.Reserve();
        int httpsPort = TestPorts.Reserve();
        string? original = Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
        Environment.SetEnvironmentVariable("ASPNETCORE_URLS", null);
        try
        {
            await using RunningApp app = await RunningApp.Start(
                _ => { },
                options => (options.HttpPort, options.HttpsPort) = (httpPort, httpsPort),
                new TestLogProvider());

            using HttpClient plain = new();
            using HttpResponseMessage response = await plain.GetAsync($"http://127.0.0.1:{httpPort}/.well-known/gameshowpro/info.json");
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_URLS", original);
        }
    }

    /// <summary>
    /// An app that configures its plain-HTTP endpoints through <c>Kestrel:Endpoints</c> (Soundling): the two-call
    /// integration still runs, Kestrel binds the configured endpoint, the library adds only the HTTPS listener (not
    /// <c>HttpPort</c>), and both serve the management endpoints.
    /// </summary>
    [TestMethod]
    public async Task HttpOnlyKestrelEndpoints_AreLeftToKestrel_AndOnlyHttpsIsAdded()
    {
        int httpPort = TestPorts.Reserve();
        int httpsPort = TestPorts.Reserve();
        int unusedHttpPort = TestPorts.Reserve();
        using TempDirectory directory = new();
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.Logging.ClearProviders();
        _ = builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Kestrel:Endpoints:Http:Url"] = $"http://127.0.0.1:{httpPort}",
            ["Soundling:HttpsPort"] = httpsPort.ToString(CultureInfo.InvariantCulture),
            ["Soundling:TlsStorageDirectory"] = directory.Path,
        });
        Assert.AreEqual(TlsCaMode.BuiltInCa, builder.AddGameshowProTlsCa(options =>
        {
            options.Product = "Soundling";
            options.AppLabel = "soundling";
            options.HttpPort = unusedHttpPort;
            options.HttpsPort = 1;
            options.ConfigurationSection = "Soundling";
            options.AdvertiseMdns = false;
        }));
        await using WebApplication app = builder.Build();
        _ = app.UseGameshowProTlsCa();
        await app.StartAsync();
        try
        {
            using HttpClient plain = new();
            JsonObject info = JsonNode.Parse(await plain.GetStringAsync($"http://127.0.0.1:{httpPort}/.well-known/gameshowpro/info.json"))!.AsObject();
            Assert.AreEqual(httpsPort, (int?)info["httpsPort"]);
            Assert.AreEqual("Soundling", (string?)info["product"]);
            byte[] caDer = await plain.GetByteArrayAsync($"http://127.0.0.1:{httpPort}/.well-known/gameshowpro/ca.crt");

            using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(caDer);
            using HttpClient secure = CreateClientTrusting(ca);
            string page = await secure.GetStringAsync($"https://{(string)info["name"]!}.local:{httpsPort}/.well-known/gameshowpro/");
            Assert.StartsWith("<!doctype html>", page);

            // HttpPort is only advertised here: Kestrel's configured endpoint is the app's HTTP listener.
            using TcpClient notBound = new();
            _ = await Assert.ThrowsAsync<SocketException>(async () => await notBound.ConnectAsync(IPAddress.Loopback, unusedHttpPort));
        }
        finally
        {
            await app.StopAsync();
        }
    }

    /// <summary>
    /// Guards the premise behind <c>KestrelTlsConfigurator</c>: with a code-defined listener Kestrel ignores the hosting URLs.
    /// If this ever fails, Kestrel changed and the re-application of the URLs must be revisited (it would bind twice).
    /// </summary>
    [TestMethod]
    public async Task Premise_KestrelIgnoresUseUrls_WhenAListenCallExists()
    {
        int urlPort = TestPorts.Reserve();
        int listenPort = TestPorts.Reserve();
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.Logging.ClearProviders();
        _ = builder.WebHost.UseUrls($"http://127.0.0.1:{urlPort}");
        _ = builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, listenPort));
        await using WebApplication app = builder.Build();
        await app.StartAsync();

        using TcpClient listening = new();
        await listening.ConnectAsync(IPAddress.Loopback, listenPort);
        using TcpClient dropped = new();
        _ = await Assert.ThrowsAsync<SocketException>(async () => await dropped.ConnectAsync(IPAddress.Loopback, urlPort));
        await app.StopAsync();
    }

    /// <summary>
    /// An <c>identity.json</c> that cannot be used does not stop the app: HTTP serves the page, the certificate endpoints
    /// answer 503, the HTTPS listener is bound but refuses every handshake without logging a warning or an error per
    /// connection, and a gated reset brings HTTPS up on the same running listener.
    /// </summary>
    [TestMethod]
    public async Task CorruptIdentity_AppStarts_HttpsRefusesHandshakes_AndAGatedResetRecoversHttpsOnTheSameListener()
    {
        int httpPort = TestPorts.Reserve();
        int httpsPort = TestPorts.Reserve();
        TestLogProvider logs = new();
        await using RunningApp app = await RunningApp.Start(
            builder => builder.WebHost.UseUrls($"http://127.0.0.1:{httpPort}"),
            options => (options.HttpPort, options.HttpsPort) = (httpPort, httpsPort),
            logs,
            path => _ = BrokenStorage.WriteCorruptIdentity(path),
            LogLevel.Debug);
        string prefix = $"http://127.0.0.1:{httpPort}/.well-known/gameshowpro";

        Assert.IsNotNull(app.Status.IdentityProblem);
        using HttpClient plain = new();
        using (HttpResponseMessage page = await plain.GetAsync(prefix + "/"))
        {
            Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
        }

        using (HttpResponseMessage info = await plain.GetAsync(prefix + "/info.json"))
        {
            Assert.AreEqual(HttpStatusCode.ServiceUnavailable, info.StatusCode);
        }

        // The HTTPS listener is bound...
        using (TcpClient tcp = new())
        {
            await tcp.ConnectAsync(IPAddress.Loopback, httpsPort);
        }

        // ...but no handshake succeeds, not even for a client that accepts any certificate. Kestrel reports each failed
        // handshake at Debug only.
        string derivedName = DeviceName.Derive(Environment.MachineName, "triggergate");
        int warningsBefore = logs.AtLeast(LogLevel.Warning).Count;
        using HttpClient anyCertificate = CreateClientAcceptingAnyCertificate();
        for (int attempt = 0; attempt < 3; attempt++)
        {
            _ = await Assert.ThrowsAsync<HttpRequestException>(() => anyCertificate.GetStringAsync($"https://{derivedName}.local:{httpsPort}/.well-known/gameshowpro/info.json"));
        }

        await WaitFor(() => logs.Messages.Count(message => message.StartsWith("Debug: Failed to authenticate HTTPS connection", StringComparison.Ordinal)) >= 3, logs);
        Assert.AreEqual(warningsBefore, logs.AtLeast(LogLevel.Warning).Count, string.Join(Environment.NewLine, logs.AtLeast(LogLevel.Warning)));

        // A gated reset from the machine itself installs an identity; the running listener serves it to the next handshake.
        using HttpResponseMessage reset = await plain.PostAsync(prefix + "/reset", new StringContent("{\"time\":1}", Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.OK, reset.StatusCode);
        JsonObject resetInfo = JsonNode.Parse(await reset.Content.ReadAsStringAsync())!.AsObject();
        Assert.IsNull(app.Status.IdentityProblem);
        byte[] caDer = await plain.GetByteArrayAsync(prefix + "/ca.crt");
        Assert.AreEqual((string?)resetInfo["caFingerprintSha256"], Fingerprint.Sha256(caDer));
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificate(caDer);
        using HttpClient secure = CreateClientTrusting(ca);
        string secureText = await secure.GetStringAsync($"https://{(string)resetInfo["name"]!}.local:{httpsPort}/.well-known/gameshowpro/info.json");
        Assert.AreEqual((string?)resetInfo["caFingerprintSha256"], (string?)JsonNode.Parse(secureText)!["caFingerprintSha256"]);

        // The unusable identity was logged once as an error, at startup; nothing since (no renewal or mDNS errors).
        Assert.HasCount(1, logs.AtLeast(LogLevel.Error), string.Join(Environment.NewLine, logs.AtLeast(LogLevel.Error)));
    }

    [TestMethod]
    public async Task StoppingTheApp_DisposesTheManager()
    {
        int httpPort = TestPorts.Reserve();
        RunningApp app = await RunningApp.Start(
            builder => builder.WebHost.UseUrls($"http://127.0.0.1:{httpPort}"),
            options => (options.HttpPort, options.HttpsPort) = (httpPort, TestPorts.Reserve()),
            new TestLogProvider());
        TlsIdentityManager manager = app.Manager;

        await app.DisposeAsync();

        _ = Assert.Throws<ObjectDisposedException>(() => manager.CurrentServerCertificate);
    }

    private static async ValueTask<Stream> ConnectToLoopback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        // The request names <name>.local; the connection goes to loopback, and TLS still validates the requested name.
        Socket socket = new(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(IPAddress.Loopback, context.DnsEndPoint.Port, cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static async Task WaitFor(Func<bool> condition, TestLogProvider logs)
    {
        for (int i = 0; i < 100 && !condition(); i++)
        {
            await Task.Delay(50);
        }

        Assert.IsTrue(condition(), string.Join(Environment.NewLine, logs.Messages.TakeLast(40)));
    }

    /// <summary>A client that would accept any server certificate it is shown: only used to show that no handshake completes.</summary>
    private static HttpClient CreateClientAcceptingAnyCertificate()
    {
        SocketsHttpHandler handler = new()
        {
            ConnectCallback = ConnectToLoopback,
            SslOptions = new() { RemoteCertificateValidationCallback = static (_, certificate, _, _) => certificate is not null },
        };
        return new(handler, disposeHandler: true);
    }

    private static HttpClient CreateClientTrusting(X509Certificate2 ca)
    {
        // The platform builds the chain against the CA alone (custom root trust, nothing from the machine's stores) and checks
        // the name in the same pass. A separate chain check in the callback is not enough on Windows: there the platform's
        // SSL policy reports a single error, so with the system trust an untrusted root masks a name mismatch.
        X509ChainPolicy policy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        };
        _ = policy.CustomTrustStore.Add(ca);
        SocketsHttpHandler handler = new()
        {
            ConnectCallback = ConnectToLoopback,
            SslOptions = new()
            {
                CertificateChainPolicy = policy,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = static (_, certificate, _, errors) => certificate is not null && errors == SslPolicyErrors.None,
            },
        };
        return new(handler, disposeHandler: true);
    }

    private sealed class RunningApp : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly TempDirectory _directory;

        private RunningApp(WebApplication app, TempDirectory directory)
        {
            _app = app;
            _directory = directory;
        }

        public TlsIdentityManager Manager => _app.Services.GetRequiredService<TlsIdentityManager>();

        public ITlsCaStatus Status => _app.Services.GetRequiredService<ITlsCaStatus>();

        public static async Task<RunningApp> Start(
            Action<WebApplicationBuilder> configureBuilder,
            Action<TlsCaOptions> configureOptions,
            TestLogProvider logs,
            Action<string>? prepareStorage = null,
            LogLevel minimumLevel = LogLevel.Information)
        {
            TempDirectory directory = new();
            prepareStorage?.Invoke(directory.Path);
            WebApplicationBuilder builder = WebApplication.CreateBuilder();
            _ = builder.Logging.ClearProviders();
            _ = builder.Logging.AddProvider(logs);
            _ = builder.Logging.SetMinimumLevel(minimumLevel);
            configureBuilder(builder);
            _ = builder.AddGameshowProTlsCa(options =>
            {
                options.Product = "TriggerGate";
                options.AppLabel = "triggergate";
                options.StorageDirectory = directory.Path;
                options.AdvertiseMdns = false;
                configureOptions(options);
            });
            WebApplication app = builder.Build();
            _ = app.MapGameshowProTlsCa();
            await app.StartAsync();
            return new(app, directory);
        }

        public async ValueTask DisposeAsync()
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
            _directory.Dispose();
        }
    }
}
