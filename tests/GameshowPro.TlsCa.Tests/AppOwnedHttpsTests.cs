namespace GameshowPro.TlsCa.Tests;

/// <summary>Real Kestrel sockets for application-owned, reloadable endpoints and TLS certificate selection.</summary>
[TestClass]
[DoNotParallelize]
public sealed class AppOwnedHttpsTests
{
    [TestMethod]
    public async Task BuiltInCertificate_RenewalAndReloadAddedEndpoint_UseCurrentLeaf()
    {
        using TempDirectory directory = new();
        int http = TestPorts.Reserve();
        int first = TestPorts.Reserve();
        int added = TestPorts.Reserve();
        using OwnedApp app = await OwnedApp.Start(directory.Path, http, first);

        Assert.AreEqual(TlsCaMode.BuiltInCa, app.Mode);
        Assert.IsTrue(app.Https.SuppliesCertificate);
        Assert.IsNotNull(app.Manager.CurrentServerCertificateOrDefault);
        CollectionAssert.Contains(app.BoundAddresses, $"http://127.0.0.1:{http}");
        CollectionAssert.Contains(app.BoundAddresses, $"https://127.0.0.1:{first}");
        byte[] before = await Leaf(first);
        CollectionAssert.AreEqual(app.Manager.CurrentServerCertificateOrDefault.RawData, before);

        using HttpClient client = new();
        using HttpResponseMessage renew = await client.PostAsync($"http://127.0.0.1:{http}/.well-known/gameshowpro/renew",
            new StringContent("{\"time\":1}", Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.OK, renew.StatusCode);
        byte[] renewed = await Leaf(first);
        Assert.IsFalse(before.AsSpan().SequenceEqual(renewed));
        CollectionAssert.AreEqual(app.Manager.CurrentServerCertificateOrDefault.RawData, renewed);

        app.AddEndpoint("Added", added);
        await Until(async () => await TryConnect(added) == 1);
        CollectionAssert.Contains(app.BoundAddresses, $"https://127.0.0.1:{added}");
        byte[] onAdded = await Leaf(added);
        CollectionAssert.AreEqual(renewed, onAdded);
        CollectionAssert.AreEqual(renewed, await Leaf(first));
    }

    [TestMethod]
    public async Task BuiltInCertificate_UnavailableIdentity_RefusesHandshake_ThenResetRecovers()
    {
        using TempDirectory directory = new();
        _ = BrokenStorage.WriteCorruptIdentity(directory.Path);
        int http = TestPorts.Reserve();
        int https = TestPorts.Reserve();
        using OwnedApp app = await OwnedApp.Start(directory.Path, http, https);
        Assert.IsTrue(app.Https.SuppliesCertificate);
        Assert.AreEqual(1, await TryConnect(https));
        Assert.IsTrue(await HandshakeRefused(https));

        using HttpClient client = new();
        using HttpResponseMessage reset = await client.PostAsync($"http://127.0.0.1:{http}/.well-known/gameshowpro/reset",
            new StringContent("{\"time\":1}", Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.OK, reset.StatusCode, await reset.Content.ReadAsStringAsync());
        Assert.IsTrue((await Leaf(https)).Length > 0);
    }

    [TestMethod]
    public async Task OwnCertificate_FileSwapAndMissingFile_AffectNextHandshake()
    {
        using TempDirectory directory = new();
        string path = Path.Combine(directory.Path, "server.pfx");
        _ = Directory.CreateDirectory(directory.Path);
        WriteCertificate(path, "first");
        int http = TestPorts.Reserve();
        int https = TestPorts.Reserve();
        using OwnedApp app = await OwnedApp.Start(directory.Path, http, https, options =>
        {
            options.CertificatePath = path;
            options.CertificatePollInterval = TimeSpan.FromMilliseconds(50);
        });
        Assert.AreEqual(TlsCaMode.OwnCertificate, app.Mode);
        Assert.IsTrue(app.Https.SuppliesCertificate);
        Assert.IsFalse(app.Logs.AtLeast(LogLevel.Warning).Any(message => message.Contains("configure a certificate", StringComparison.Ordinal)));
        byte[] before = await Leaf(https);

        int added = TestPorts.Reserve();
        app.AddEndpoint("OwnAdded", added);
        await Until(async () => await TryConnect(added) == 1);
        CollectionAssert.AreEqual(before, await Leaf(added));

        WriteCertificate(path, "second-longer");
        await Until(async () =>
        {
            try { byte[] current = await Leaf(https); return !before.AsSpan().SequenceEqual(current); }
            catch (Exception ex) when (ex is AuthenticationException or IOException) { return false; }
        });
        byte[] after = await Leaf(https);
        CollectionAssert.AreEqual(after, await Leaf(added));
        File.Delete(path);
        await Until(async () =>
        {
            try { _ = await Leaf(https); return false; }
            catch (Exception ex) when (ex is AuthenticationException or IOException) { return true; }
        });
        Assert.AreEqual(1, await TryConnect(https));
        Assert.IsFalse(app.Logs.AtLeast(LogLevel.Warning).Any(message => message.Contains("authenticate HTTPS connection", StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task OwnCertificate_MissingInitially_LeavesSocketBoundAndRefusesHandshake()
    {
        using TempDirectory directory = new();
        int http = TestPorts.Reserve();
        int https = TestPorts.Reserve();
        using OwnedApp app = await OwnedApp.Start(directory.Path, http, https, options =>
            options.CertificatePath = Path.Combine(directory.Path, "absent.pfx"));
        Assert.AreEqual(TlsCaMode.OwnCertificate, app.Mode);
        Assert.IsTrue(app.Https.SuppliesCertificate);
        CollectionAssert.AreEquivalent(new[] { $"http://127.0.0.1:{http}", $"https://127.0.0.1:{https}" }, app.BoundAddresses);
        Assert.AreEqual(1, await TryConnect(https));
        int errorsBefore = app.Logs.AtLeast(LogLevel.Error).Count;
        Assert.IsTrue(await HandshakeRefused(https));
        Assert.AreEqual(errorsBefore, app.Logs.AtLeast(LogLevel.Error).Count,
            "A missing certificate is logged on load, not as an unhandled server error for each handshake.");
    }

    [TestMethod]
    public async Task OwnCertificate_ConfigurationContextCarriesIntermediate()
    {
        using TestChain chain = TestChain.Create(withIntermediate: true);
        using TempDirectory directory = new();
        string path = chain.WritePfx(directory.Path, "test-password");
        using OwnedApp app = await OwnedApp.Start(directory.Path, TestPorts.Reserve(), TestPorts.Reserve(), options =>
        {
            options.CertificatePath = path;
            options.CertificatePassword = "test-password";
        });
        OwnCertificate current = app.OwnSource.Current!;
        Assert.IsNotNull(current);
        Assert.AreEqual(1, current.IntermediateCount);
        Assert.IsNotNull(current.Context);
        Assert.AreEqual(OperatingSystem.IsWindows() ? 0 : 1, current.Context.IntermediateCertificates.Count);
        // The HTTPS defaults callback uses this same source, including the context's intermediate collection.
        HttpsConnectionAdapterOptions configured = new();
        app.Https.Configure(configured);
        Assert.IsNotNull(configured.OnAuthenticate);
        Assert.IsNotNull(configured.ServerCertificateSelector);
        SslServerAuthenticationOptions handshake = new()
        {
            ServerCertificateSelectionCallback = (_, _) => current.ServerCertificate,
        };
        configured.OnAuthenticate!(new DefaultConnectionContext(), handshake);
        Assert.IsNull(handshake.ServerCertificateSelectionCallback);
        Assert.AreSame(current.Context, handshake.ServerCertificateContext);
    }

    [TestMethod]
    [DataRow(false, false)]
    [DataRow(false, true)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public async Task AppOwnsListeners_DoesNotAddHttpOrHttps(bool off, bool useUrls)
    {
        using TempDirectory directory = new();
        int http = TestPorts.Reserve();
        int https = TestPorts.Reserve();
        int actual = TestPorts.Reserve();
        int ignoredUrl = TestPorts.Reserve();
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.Logging.ClearProviders();
        _ = builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, actual));
        if (useUrls)
        {
            _ = builder.WebHost.UseUrls($"http://127.0.0.1:{ignoredUrl}");
        }
        TlsCaMode mode = builder.AddGameshowProTlsCa(options =>
        {
            options.Product = "Test";
            options.AppLabel = "test";
            options.StorageDirectory = directory.Path;
            options.HttpPort = http;
            options.HttpsPort = off ? 0 : https;
            options.AppOwnsListeners = true;
            options.AdvertiseMdns = false;
        });
        Assert.AreEqual(off ? TlsCaMode.Off : TlsCaMode.BuiltInCa, mode);
        await using WebApplication app = builder.Build();
        ITlsCaHttps tls = app.Services.GetRequiredService<ITlsCaHttps>();
        Assert.AreEqual(mode == TlsCaMode.BuiltInCa, tls.SuppliesCertificate);
        if (!tls.SuppliesCertificate)
        {
            HttpsConnectionAdapterOptions untouched = new();
            tls.Configure(untouched);
            Assert.IsNull(untouched.ServerCertificateSelector);
            Assert.IsNull(untouched.OnAuthenticate);
        }
        await app.StartAsync();
        try
        {
            string[] addresses = [.. app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses];
            CollectionAssert.AreEquivalent(new[] { $"http://127.0.0.1:{actual}" }, addresses);
            Assert.AreEqual(0, await TryConnect(http));
            Assert.AreEqual(0, await TryConnect(https));
            Assert.AreEqual(0, await TryConnect(ignoredUrl));
        }
        finally { await app.StopAsync(); }
    }

    [TestMethod]
    public async Task KestrelCertificate_RegistersNoCertificateSupplier_AndBindsOnlyAppEndpoint()
    {
        using TempDirectory directory = new();
        int configuredHttps = TestPorts.Reserve();
        int libraryHttp = TestPorts.Reserve();
        int libraryHttps = TestPorts.Reserve();
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Configuration["Kestrel:Endpoints:External:Url"] = $"https://127.0.0.1:{configuredHttps}";
        _ = builder.WebHost.ConfigureKestrel(kestrel => kestrel.ConfigureHttpsDefaults(https =>
            https.ServerCertificateSelector = static (_, _) => null));
        TlsCaMode mode = builder.AddGameshowProTlsCa(options =>
        {
            options.Product = "Test";
            options.AppLabel = "test";
            options.StorageDirectory = directory.Path;
            options.HttpPort = libraryHttp;
            options.HttpsPort = libraryHttps;
            options.AppOwnsListeners = true;
            options.AdvertiseMdns = false;
        });
        Assert.AreEqual(TlsCaMode.KestrelCertificate, mode);
        await using WebApplication app = builder.Build();
        ITlsCaHttps tls = app.Services.GetRequiredService<ITlsCaHttps>();
        Assert.IsFalse(tls.SuppliesCertificate);
        HttpsConnectionAdapterOptions untouched = new();
        tls.Configure(untouched);
        Assert.IsNull(untouched.ServerCertificateSelector);
        Assert.IsNull(untouched.OnAuthenticate);
        Assert.IsFalse(builder.Services.Any(descriptor => descriptor.ImplementationType == typeof(KestrelTlsConfigurator)));
        await app.StartAsync();
        try
        {
            string[] addresses = [.. app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses];
            CollectionAssert.AreEquivalent(new[] { $"https://127.0.0.1:{configuredHttps}" }, addresses);
            Assert.AreEqual(0, await TryConnect(libraryHttp));
            Assert.AreEqual(0, await TryConnect(libraryHttps));
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private static void WriteCertificate(string path, string name)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pkcs12));
    }

    // A server with no certificate ends the handshake; the client sees that as an authentication failure or as the
    // connection closing, depending on how far the handshake got.
    private static async Task<bool> HandshakeRefused(int port)
    {
        try { _ = await Leaf(port); return false; }
        catch (Exception ex) when (ex is AuthenticationException or IOException) { return true; }
    }

    private static async Task<byte[]> Leaf(int port)
    {
        using TcpClient client = new();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using SslStream ssl = new(client.GetStream(), false, static (_, certificate, _, _) => certificate is not null);
        await ssl.AuthenticateAsClientAsync("localhost");
        return ssl.RemoteCertificate!.Export(X509ContentType.Cert);
    }

    private static async Task<int> TryConnect(int port)
    {
        using TcpClient client = new();
        try { await client.ConnectAsync(IPAddress.Loopback, port); return 1; }
        catch (SocketException) { return 0; }
    }

    private static async Task Until(Func<Task<bool>> condition)
    {
        for (int i = 0; i < 100; i++)
        {
            if (await condition())
            {
                return;
            }
            await Task.Delay(50);
        }
        Assert.Fail("Condition did not become true within five seconds.");
    }

    private sealed class OwnedApp : IDisposable
    {
        private readonly WebApplication _app;
        private readonly IConfigurationRoot _listeners;

        private OwnedApp(WebApplication app, IConfigurationRoot listeners, TlsCaMode mode)
        {
            _app = app;
            _listeners = listeners;
            Mode = mode;
            Https = app.Services.GetRequiredService<ITlsCaHttps>();
        }

        public TlsCaMode Mode { get; }
        public ITlsCaHttps Https { get; }
        public TlsIdentityManager Manager => _app.Services.GetRequiredService<TlsIdentityManager>();
        public OwnCertificateSource OwnSource => _app.Services.GetRequiredService<OwnCertificateSource>();
        public TestLogProvider Logs { get; private init; } = null!;
        public string[] BoundAddresses => [.. _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses];

        public static async Task<OwnedApp> Start(string storage, int http, int https, Action<TlsCaOptions>? change = null)
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder();
            _ = builder.Logging.ClearProviders();
            TestLogProvider logs = new();
            _ = builder.Logging.AddProvider(logs);
            _ = builder.Logging.SetMinimumLevel(LogLevel.Debug);
            IConfigurationRoot listeners = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Kestrel:Endpoints:Http:Url"] = $"http://127.0.0.1:{http}",
                ["Kestrel:Endpoints:Https:Url"] = $"https://127.0.0.1:{https}",
            }).Build();
            TlsCaMode mode = builder.AddGameshowProTlsCa(options =>
            {
                options.Product = "Test";
                options.AppLabel = "test";
                options.StorageDirectory = storage;
                options.HttpPort = http;
                options.HttpsPort = https;
                options.AppOwnsListeners = true;
                options.AdvertiseMdns = false;
                change?.Invoke(options);
            });
            ITlsCaHttps? tls = null;
            _ = builder.WebHost.ConfigureKestrel(kestrel =>
            {
                _ = kestrel.Configure(listeners.GetSection("Kestrel"), reloadOnChange: true);
                kestrel.ConfigureHttpsDefaults(httpsOptions => tls!.Configure(httpsOptions));
            });
            WebApplication app = builder.Build();
            tls = app.Services.GetRequiredService<ITlsCaHttps>();
            _ = app.MapGameshowProTlsCa();
            await app.StartAsync();
            return new(app, listeners, mode) { Logs = logs };
        }

        public void AddEndpoint(string name, int port)
        {
            _listeners[$"Kestrel:Endpoints:{name}:Url"] = $"https://127.0.0.1:{port}";
            _listeners.Reload();
        }

        public void Dispose()
        {
            _app.StopAsync().GetAwaiter().GetResult();
            _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }
}
