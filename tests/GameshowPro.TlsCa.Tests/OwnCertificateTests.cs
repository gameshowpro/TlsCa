namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// <see cref="TlsCaMode.OwnCertificate"/>, <see cref="TlsCaMode.KestrelCertificate"/> and <see cref="TlsCaMode.Off"/>:
/// real handshakes with a PKCS#12 and a PEM certificate where the client trusts only the test root (custom root trust;
/// nothing is added to any certificate store), reload without a restart, a bad file then a fixed one, the expiry warning,
/// and every endpoint in every mode without the built-in CA.
/// </summary>
[TestClass]
[DoNotParallelize]
public sealed class OwnCertificateTests
{
    private const string Prefix = "/.well-known/gameshowpro";
    private const string DnsName = "server.example.test";
    private const string Password = "pfx-pass-7f3a";

    private static readonly string[] s_ownInfoFields = ["product", "httpsPort", "version", "certificateSource", "certificateNotAfter", "certificateDnsNames", "secureAddress", "setupAddress", "fallbackAddress", "fallbackAddresses", "allowHttpFallback"];
    private static readonly string[] s_plainInfoFields = ["product", "httpsPort", "version", "certificateSource", "secureAddress", "setupAddress", "fallbackAddress", "fallbackAddresses", "allowHttpFallback"];

    // Handshakes

    [TestMethod]
    [DataRow(SslProtocols.Tls12)]
    [DataRow(SslProtocols.Tls13)]
    public async Task Pfx_IssuedByTheRoot_ClientTrustingOnlyTheRootValidates(SslProtocols protocol)
    {
        if (protocol == SslProtocols.Tls13 && OperatingSystem.IsWindows() && !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348))
        {
            Assert.Inconclusive("This Windows version has no TLS 1.3 server.");
        }

        using TestChain chain = TestChain.Create(withIntermediate: false);
        using TempDirectory files = new();
        string pfx = chain.WritePfx(files.Path, Password);
        TestLogProvider logs = new();
        await using OwnApp app = await OwnApp.Start(options => (options.CertificatePath, options.CertificatePassword) = (pfx, Password), logs);

        HandshakeResult result = await Handshake(app.HttpsPort, DnsName, chain.Root, protocol);

        Assert.IsTrue(result.Connected, result.Errors.ToString());
        Assert.AreEqual(protocol, result.Protocol);
        CollectionAssert.AreEqual(chain.Leaf.RawData, result.Leaf);
        Assert.AreEqual(TlsCaMode.OwnCertificate, app.Status.Mode);
        Assert.IsNull(app.Status.Problem);
        CollectionAssert.AreEqual(new[] { DnsName }, app.Status.CertificateDnsNames.ToArray());
        Assert.AreEqual(new DateTimeOffset(chain.Leaf.NotAfter.ToUniversalTime(), TimeSpan.Zero), app.Status.CertificateNotAfter);
        Assert.AreEqual($"https://{DnsName}:{app.HttpsPort}/", app.Status.SecureAddress);
        Assert.IsNull(app.Status.SetupAddress);

        // One Information line names the port, the file, the subject, the names and the expiry; the password is never logged.
        string loaded = logs.Messages.Single(message => message.StartsWith("Information: HTTPS on port", StringComparison.Ordinal));
        StringAssert.Contains(loaded, app.HttpsPort.ToString(CultureInfo.InvariantCulture));
        StringAssert.Contains(loaded, pfx);
        StringAssert.Contains(loaded, chain.Leaf.Subject);
        StringAssert.Contains(loaded, DnsName);
        StringAssert.Contains(loaded, "built-in CA is not used");
        Assert.IsFalse(logs.Messages.Any(message => message.Contains(Password, StringComparison.Ordinal)));
        Assert.IsFalse(Directory.Exists(app.StorageDirectory), "The storage directory must not be touched.");
    }

    [TestMethod]
    [DataRow(PemKey.SeparateFile)]
    [DataRow(PemKey.InCertificateFile)]
    [DataRow(PemKey.Encrypted)]
    [DataRow(PemKey.Rsa)]
    public async Task Pem_IssuedByTheRoot_ClientTrustingOnlyTheRootValidates(PemKey key)
    {
        using TestChain chain = TestChain.Create(withIntermediate: false, rsa: key == PemKey.Rsa);
        using TempDirectory files = new();
        (string certificate, string? keyFile) = chain.WritePem(files.Path, keyInCertificateFile: key == PemKey.InCertificateFile, password: key == PemKey.Encrypted ? Password : null);
        await using OwnApp app = await OwnApp.Start(
            options => (options.CertificatePath, options.CertificateKeyPath, options.CertificatePassword) = (certificate, keyFile, key == PemKey.Encrypted ? Password : null),
            new TestLogProvider());

        HandshakeResult result = await Handshake(app.HttpsPort, DnsName, chain.Root, SslProtocols.Tls12);

        Assert.IsTrue(result.Connected, $"{result.Errors} {app.Status.Problem}");
        CollectionAssert.AreEqual(chain.Leaf.RawData, result.Leaf);
    }

    /// <summary>Root, intermediate and leaf: the intermediate travels in the handshake, so a client that has only the root validates.</summary>
    [TestMethod]
    [OSCondition(OperatingSystems.Linux)]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Chain_TheIntermediateIsSent_AndAClientTrustingOnlyTheRootValidates(bool pem)
    {
        using TestChain chain = TestChain.Create(withIntermediate: true);
        using TempDirectory files = new();
        string? keyFile = null;
        string certificate = pem ? Unpack(chain.WritePem(files.Path, keyInCertificateFile: false, password: null), out keyFile) : chain.WritePfx(files.Path, Password);
        await using OwnApp app = await OwnApp.Start(
            options => (options.CertificatePath, options.CertificateKeyPath, options.CertificatePassword) = (certificate, keyFile, pem ? null : Password),
            new TestLogProvider());

        HandshakeResult result = await Handshake(app.HttpsPort, DnsName, chain.Root, SslProtocols.Tls12);

        Assert.IsTrue(result.Connected, $"{result.Errors} {app.Status.Problem}");
        Assert.IsTrue(result.AlsoSent.Any(der => der.AsSpan().SequenceEqual(chain.Intermediate!.RawData)), "The intermediate was not sent.");
    }

    /// <summary>
    /// On Windows, SChannel sends only what the machine's stores can chain, and .NET would add the intermediate to a store
    /// to make that work; the library never lets it, so only the leaf is sent and a warning says so.
    /// </summary>
    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    public async Task Chain_OnWindows_OnlyTheLeafIsSent_AndAWarningSaysSo()
    {
        using TestChain chain = TestChain.Create(withIntermediate: true);
        using TempDirectory files = new();
        string pfx = chain.WritePfx(files.Path, Password);
        TestLogProvider logs = new();
        await using OwnApp app = await OwnApp.Start(options => (options.CertificatePath, options.CertificatePassword) = (pfx, Password), logs);

        HandshakeResult result = await Handshake(app.HttpsPort, DnsName, chain.Root, SslProtocols.Tls12);

        CollectionAssert.AreEqual(chain.Leaf.RawData, result.Leaf);
        Assert.IsFalse(result.AlsoSent.Any(der => der.AsSpan().SequenceEqual(chain.Intermediate!.RawData)));
        Assert.AreEqual(1, logs.AtLeast(LogLevel.Warning).Count(message => message.Contains("not sent in the TLS handshake", StringComparison.Ordinal)));
    }

    // Reload

    [TestMethod]
    public async Task ReplacedFile_IsServedWithoutARestart()
    {
        using TestChain first = TestChain.Create(withIntermediate: false);
        using TestChain second = TestChain.Create(withIntermediate: false);
        using TempDirectory files = new();
        string pfx = first.WritePfx(files.Path, Password);
        TestLogProvider logs = new();
        await using OwnApp app = await OwnApp.Start(options => (options.CertificatePath, options.CertificatePassword) = (pfx, Password), logs);
        int changed = 0;
        app.Status.Changed += (_, _) => Interlocked.Increment(ref changed);
        CollectionAssert.AreEqual(first.Leaf.RawData, (await Handshake(app.HttpsPort, DnsName, first.Root, SslProtocols.Tls12)).Leaf);

        Replace(pfx, second.Pfx(Password));

        await WaitFor(async () => (await Handshake(app.HttpsPort, DnsName, second.Root, SslProtocols.Tls12)).Connected, logs);
        CollectionAssert.AreEqual(second.Leaf.RawData, (await Handshake(app.HttpsPort, DnsName, second.Root, SslProtocols.Tls12)).Leaf);
        Assert.IsGreaterThanOrEqualTo(1, Volatile.Read(ref changed));
        Assert.IsTrue(logs.Messages.Any(message => message.StartsWith("Information: The certificate file", StringComparison.Ordinal) && message.Contains("changed", StringComparison.Ordinal)));
    }

    [TestMethod]
    public async Task MissingThenBadThenFixedFile_HandshakesFailUntilFixed_AndTheBuiltInCaIsNeverUsed()
    {
        using TestChain chain = TestChain.Create(withIntermediate: false);
        using TempDirectory files = new();
        _ = Directory.CreateDirectory(files.Path);
        string pfx = Path.Combine(files.Path, "server.pfx");
        TestLogProvider logs = new();
        await using OwnApp app = await OwnApp.Start(options => (options.CertificatePath, options.CertificatePassword) = (pfx, Password), logs, LogLevel.Debug);

        // Missing: logged as an error, Problem set, the listener bound, handshakes refused.
        Assert.IsNotNull(app.Status.Problem);
        StringAssert.Contains(app.Status.Problem, pfx);
        Assert.IsNull(app.Status.CertificateNotAfter);
        Assert.IsNull(app.Status.SecureAddress);
        Assert.HasCount(1, logs.AtLeast(LogLevel.Error));
        using (TcpClient tcp = new())
        {
            await tcp.ConnectAsync(IPAddress.Loopback, app.HttpsPort);
        }

        Assert.IsFalse((await Handshake(app.HttpsPort, DnsName, chain.Root, SslProtocols.Tls12)).Connected);
        JsonObject info = await app.GetInfo();
        CollectionAssert.AreEquivalent(s_plainInfoFields, info.Select(pair => pair.Key).ToArray());
        Assert.AreEqual("own", (string?)info["certificateSource"]);

        // Bad content: a second error, still no certificate.
        Replace(pfx, Encoding.UTF8.GetBytes("not a certificate"));
        await WaitFor(() => Task.FromResult(logs.AtLeast(LogLevel.Error).Count >= 2), logs);
        Assert.IsNotNull(app.Status.Problem);
        Assert.IsFalse((await Handshake(app.HttpsPort, DnsName, chain.Root, SslProtocols.Tls12)).Connected);

        // Fixed: served on the same listener without a restart.
        Replace(pfx, chain.Pfx(Password));
        await WaitFor(async () => (await Handshake(app.HttpsPort, DnsName, chain.Root, SslProtocols.Tls12)).Connected, logs);
        Assert.IsNull(app.Status.Problem);
        Assert.IsNotNull(app.Status.CertificateNotAfter);
        Assert.AreEqual($"https://{DnsName}:{app.HttpsPort}/", app.Status.SecureAddress);
        CollectionAssert.AreEquivalent(s_ownInfoFields, (await app.GetInfo()).Select(pair => pair.Key).ToArray());

        // Failed handshakes were Debug only; nothing about the built-in CA, and its storage was never touched.
        Assert.IsFalse(logs.AtLeast(LogLevel.Warning).Any(message => message.Contains("authenticate", StringComparison.OrdinalIgnoreCase)), string.Join(Environment.NewLine, logs.AtLeast(LogLevel.Warning)));
        Assert.IsFalse(Directory.Exists(app.StorageDirectory));
        Assert.IsNull(app.Services.GetService<TlsIdentityManager>());
    }

    // Expiry

    [TestMethod]
    public async Task ExpiresWithin30Days_WarnsAtStartup_AndAgainADayLater()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using TestChain chain = TestChain.Create(withIntermediate: false, notAfter: now.AddDays(10));
        using TempDirectory files = new();
        string pfx = chain.WritePfx(files.Path, Password);
        ManualTimeProvider time = new(now);
        TestLogProvider logs = new();
        await using TestServerApp app = await TestServerApp.Start(
            options => (options.CertificatePath, options.CertificatePassword) = (pfx, Password),
            logs,
            time: time);

        int Warnings() => logs.AtLeast(LogLevel.Warning).Count(message => message.Contains("expires at", StringComparison.Ordinal));
        Assert.AreEqual(1, Warnings());
        StringAssert.Contains(logs.AtLeast(LogLevel.Warning)[0], "in 10 days");

        await Task.Delay(400);
        Assert.AreEqual(1, Warnings(), "Repeated before a day passed.");

        time.Now = now.AddDays(1).AddMinutes(1);
        await WaitFor(() => Task.FromResult(Warnings() == 2), logs);
    }

    [TestMethod]
    public async Task Expired_IsServedWithAWarning()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using TestChain chain = TestChain.Create(withIntermediate: false, notAfter: now.AddDays(-1));
        using TempDirectory files = new();
        string pfx = chain.WritePfx(files.Path, Password);
        TestLogProvider logs = new();
        await using TestServerApp app = await TestServerApp.Start(options => (options.CertificatePath, options.CertificatePassword) = (pfx, Password), logs);

        Assert.AreEqual(1, logs.AtLeast(LogLevel.Warning).Count(message => message.Contains("expired at", StringComparison.Ordinal)));
        Assert.IsNull(app.Status.Problem);
    }

    // Endpoints in every mode without the built-in CA

    public enum NonCaMode
    {
        OwnLoaded,
        OwnUnloadable,
        Kestrel,
        Off,
    }

    [TestMethod]
    [DataRow(NonCaMode.OwnLoaded)]
    [DataRow(NonCaMode.OwnUnloadable)]
    [DataRow(NonCaMode.Kestrel)]
    [DataRow(NonCaMode.Off)]
    public async Task EveryEndpoint_WithoutTheBuiltInCa(NonCaMode mode)
    {
        using TestChain chain = TestChain.Create(withIntermediate: false);
        using TempDirectory files = new();
        string pfx = mode == NonCaMode.OwnLoaded ? chain.WritePfx(files.Path, Password) : Path.Combine(files.Path, "missing", "server.pfx");
        (string, string?)[] configuration = mode switch
        {
            NonCaMode.Kestrel => [("Kestrel:Endpoints:Https:Url", "https://*:9443")],
            NonCaMode.Off => [("TriggerGate:HttpsPort", "0")],
            NonCaMode.OwnLoaded or NonCaMode.OwnUnloadable => [("TriggerGate:CertificatePath", pfx), ("TriggerGate:CertificatePassword", Password)],
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
        TestLogProvider logs = new();
        await using TestServerApp app = await TestServerApp.Start(_ => { }, logs, configuration);
        TlsCaMode expectedMode = mode switch
        {
            NonCaMode.Kestrel => TlsCaMode.KestrelCertificate,
            NonCaMode.Off => TlsCaMode.Off,
            NonCaMode.OwnLoaded or NonCaMode.OwnUnloadable => TlsCaMode.OwnCertificate,
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
        Assert.AreEqual(expectedMode, app.Status.Mode);
        Assert.AreEqual(mode == NonCaMode.OwnUnloadable, app.Status.Problem is not null);
        Assert.IsNull(app.Status.IdentityProblem);
        Assert.AreEqual("", app.Status.MdnsName);
        Assert.AreEqual("", app.Status.CaFingerprintSha256);
        Assert.AreEqual(mode == NonCaMode.OwnLoaded ? $"https://{DnsName}:9443/" : null, app.Status.SecureAddress);
        Assert.IsNull(app.Status.SetupAddress);
        List<string> bodies = [];

        // The page is a short static notice with the page's security headers: no script, no buttons, no downloads.
        using (HttpResponseMessage page = await app.Get(Prefix + "/"))
        {
            Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
            Assert.AreEqual("text/html", page.Content.Headers.ContentType?.MediaType);
            Assert.AreEqual("no-store", page.Headers.CacheControl?.ToString());
            Assert.AreEqual("nosniff", page.Headers.GetValues("X-Content-Type-Options").Single());
            StringAssert.Contains(page.Headers.GetValues("Content-Security-Policy").Single(), "frame-ancestors 'none'");
            string html = await page.Content.ReadAsStringAsync();
            Assert.StartsWith("<!doctype html>", html);
            foreach (string absent in new[] { "<script", "<button", "<form", "ca.crt", "ca.pem", "mobileconfig", "href=" })
            {
                Assert.DoesNotContain(absent, html, StringComparison.OrdinalIgnoreCase);
            }

            bodies.Add(html);
        }

        foreach (string download in new[] { "/ca.crt", "/ca.pem", "/ca.mobileconfig" })
        {
            using HttpResponseMessage response = await app.Get(Prefix + download);
            Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode, download);
            Assert.AreEqual("text/plain", response.Content.Headers.ContentType?.MediaType, download);
            Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString(), download);
            string text = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(text, "does not use a GameshowPro certificate authority");
            bodies.Add(text);
        }

        using (HttpResponseMessage infoResponse = await app.Get(Prefix + "/info.json"))
        {
            Assert.AreEqual(HttpStatusCode.OK, infoResponse.StatusCode);
            Assert.AreEqual("*", infoResponse.Headers.GetValues("Access-Control-Allow-Origin").Single());
            Assert.AreEqual("no-store", infoResponse.Headers.CacheControl?.ToString());
            string text = await infoResponse.Content.ReadAsStringAsync();
            bodies.Add(text);
            JsonObject info = JsonNode.Parse(text)!.AsObject();
            CollectionAssert.AreEquivalent(mode == NonCaMode.OwnLoaded ? s_ownInfoFields : s_plainInfoFields, info.Select(pair => pair.Key).ToArray());
            Assert.AreEqual("TriggerGate", (string?)info["product"]);
            Assert.AreEqual("2.1.7", (string?)info["version"]);
            Assert.AreEqual(mode == NonCaMode.Off ? "off" : "own", (string?)info["certificateSource"]);
            Assert.AreEqual(mode == NonCaMode.Off ? 0 : 9443, (int?)info["httpsPort"]);
            Assert.AreEqual(mode == NonCaMode.OwnLoaded ? $"https://{DnsName}:9443/" : null, (string?)info["secureAddress"]);
            Assert.IsNull(info["setupAddress"]);
            Assert.AreEqual(false, (bool?)info["allowHttpFallback"]);
            if (mode == NonCaMode.OwnLoaded)
            {
                Assert.AreEqual(new DateTimeOffset(chain.Leaf.NotAfter.ToUniversalTime(), TimeSpan.Zero).ToUnixTimeSeconds(), (long?)info["certificateNotAfter"]);
                CollectionAssert.AreEqual(new[] { DnsName }, info["certificateDnsNames"]!.AsArray().Select(name => (string?)name).ToArray());
            }
        }

        // Renew and reset: 409 before the gate (a non-loopback remote gets the same answer); 415 first for non-JSON.
        foreach (string action in new[] { "/renew", "/reset" })
        {
            foreach (string? remote in new[] { null, "192.168.1.50" })
            {
                using HttpResponseMessage response = await app.PostJson(Prefix + action, remote);
                Assert.AreEqual(HttpStatusCode.Conflict, response.StatusCode, action);
                Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString(), action);
                string text = await response.Content.ReadAsStringAsync();
                StringAssert.Contains((string?)JsonNode.Parse(text)!["error"], "nothing to renew or reset");
                bodies.Add(text);
            }

            using HttpResponseMessage notJson = await app.Send(HttpMethod.Post, Prefix + action, new StringContent("{}", Encoding.UTF8, "text/plain"));
            Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, notJson.StatusCode, action);
            using HttpResponseMessage get = await app.Get(Prefix + action);
            Assert.AreEqual(HttpStatusCode.MethodNotAllowed, get.StatusCode, action);
        }

        using (HttpResponseMessage unknown = await app.Get(Prefix + "/nothing"))
        {
            Assert.AreEqual(HttpStatusCode.NotFound, unknown.StatusCode);
        }

        // No HTTP root redirect: the app's own pipeline answers.
        using (HttpResponseMessage root = await app.Get("http://pi.local:9090/"))
        {
            Assert.AreEqual(HttpStatusCode.OK, root.StatusCode);
            Assert.AreEqual("fallback", await root.Content.ReadAsStringAsync());
        }

        // No response carries a path, a password or exception text.
        foreach (string body in bodies)
        {
            Assert.DoesNotContain(files.Path, body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Password, body, StringComparison.Ordinal);
            Assert.DoesNotContain("Exception", body, StringComparison.Ordinal);
        }

        Assert.IsFalse(Directory.Exists(app.StorageDirectory), "The storage directory must not be touched.");
        Assert.IsNull(app.Services.GetService<TlsIdentityManager>());
    }

    [TestMethod]
    public async Task ModeLines_AreLoggedOnce()
    {
        TestLogProvider kestrelLogs = new();
        await using (TestServerApp _ = await TestServerApp.Start(_ => { }, kestrelLogs, [("Kestrel:Endpoints:Https:Url", "https://*:9443")]))
        {
            Assert.AreEqual(1, kestrelLogs.Messages.Count(message => message.StartsWith("Information: HTTPS uses the certificate Kestrel is configured with (Kestrel:Endpoints:Https:Url)", StringComparison.Ordinal)));
        }

        TestLogProvider offLogs = new();
        await using (TestServerApp _ = await TestServerApp.Start(_ => { }, offLogs, [("TriggerGate:HttpsPort", "0")]))
        {
            Assert.AreEqual(1, offLogs.Messages.Count(message => message.StartsWith("Information: HTTPS is off", StringComparison.Ordinal)));
        }

        using TestChain chain = TestChain.Create(withIntermediate: false);
        using TempDirectory files = new();
        string pfx = chain.WritePfx(files.Path, Password);
        TestLogProvider bothLogs = new();
        await using (TestServerApp _ = await TestServerApp.Start(
            _ => { },
            bothLogs,
            [("TriggerGate:CertificatePath", pfx), ("TriggerGate:CertificatePassword", Password), ("Kestrel:Endpoints:Https:Url", "https://*:9443")]))
        {
            string warning = bothLogs.AtLeast(LogLevel.Warning).Single(message => message.Contains("configure a certificate", StringComparison.Ordinal));
            StringAssert.Contains(warning, "TriggerGate:CertificatePath");
            StringAssert.Contains(warning, pfx);
            StringAssert.Contains(warning, "Kestrel:Endpoints:Https:Url");
        }
    }

    // Helpers

    public enum PemKey
    {
        SeparateFile,
        InCertificateFile,
        Encrypted,
        Rsa,
    }

    private static string Unpack((string Certificate, string? Key) files, out string? key)
    {
        key = files.Key;
        return files.Certificate;
    }

    /// <summary>Replaces <paramref name="path"/> in one step (a temporary file renamed over it).</summary>
    private static void Replace(string path, byte[] content)
    {
        string temporary = path + ".tmp";
        File.WriteAllBytes(temporary, content);
        File.Move(temporary, path, overwrite: true);
    }

    private static async Task WaitFor(Func<Task<bool>> condition, TestLogProvider logs)
    {
        for (int i = 0; i < 100; i++)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(100);
        }

        Assert.Fail(string.Join(Environment.NewLine, logs.Messages.TakeLast(30)));
    }

    /// <summary>A TLS client that trusts only <paramref name="root"/> (custom root trust), connecting to loopback and validating <paramref name="host"/>.</summary>
    private static async Task<HandshakeResult> Handshake(int port, string host, X509Certificate2 root, SslProtocols protocol)
    {
        using TcpClient tcp = new();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        await using SslStream ssl = new(tcp.GetStream(), leaveInnerStreamOpen: false);
        X509ChainPolicy policy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        };
        _ = policy.CustomTrustStore.Add(root);
        SslPolicyErrors errors = SslPolicyErrors.None;
        byte[]? leaf = null;
        byte[][] alsoSent = [];
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = protocol,
                CertificateChainPolicy = policy,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = ValidateCertificate,
            });
            return new(true, errors, leaf, alsoSent, ssl.SslProtocol);
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException)
        {
            return new(false, errors, leaf, alsoSent, SslProtocols.None);
        }

        bool ValidateCertificate(object _, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            errors = sslPolicyErrors;
            leaf = certificate?.GetRawCertData();
            alsoSent = [.. (chain?.ChainPolicy.ExtraStore ?? []).Select(c => c.RawData).Where(der => leaf is null || !der.AsSpan().SequenceEqual(leaf))];
            return sslPolicyErrors == SslPolicyErrors.None;
        }
    }

    /// <summary>Real Kestrel on loopback in <see cref="TlsCaMode.OwnCertificate"/>, checking the files every 100 ms.</summary>
    private sealed class OwnApp : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly TempDirectory _storage;
        private readonly int _httpPort;

        private OwnApp(WebApplication app, TempDirectory storage, int httpPort, int httpsPort)
        {
            _app = app;
            _storage = storage;
            _httpPort = httpPort;
            HttpsPort = httpsPort;
        }

        public int HttpsPort { get; }

        public string StorageDirectory => _storage.Path;

        public IServiceProvider Services => _app.Services;

        public ITlsCaStatus Status => _app.Services.GetRequiredService<ITlsCaStatus>();

        public static async Task<OwnApp> Start(Action<TlsCaOptions> configure, TestLogProvider logs, LogLevel minimumLevel = LogLevel.Information)
        {
            int httpPort = TestPorts.Reserve();
            int httpsPort = TestPorts.Reserve();
            TempDirectory storage = new();
            WebApplicationBuilder builder = WebApplication.CreateBuilder();
            _ = builder.Logging.ClearProviders();
            _ = builder.Logging.AddProvider(logs);
            _ = builder.Logging.SetMinimumLevel(minimumLevel);
            _ = builder.WebHost.UseUrls($"http://127.0.0.1:{httpPort}");
            TlsCaMode mode = builder.AddGameshowProTlsCa(ConfigureOptions);
            Assert.AreEqual(TlsCaMode.OwnCertificate, mode);
            WebApplication app = builder.Build();
            _ = app.UseGameshowProTlsCa();
            await app.StartAsync();
            return new(app, storage, httpPort, httpsPort);

            void ConfigureOptions(TlsCaOptions options)
            {
                options.Product = "TriggerGate";
                options.AppLabel = "triggergate";
                options.StorageDirectory = storage.Path;
                options.HttpPort = httpPort;
                options.HttpsPort = httpsPort;
                options.AdvertiseMdns = false;
                options.CertificatePollInterval = TimeSpan.FromMilliseconds(100);
                configure(options);
            }
        }

        public async Task<JsonObject> GetInfo()
        {
            using HttpClient client = new();
            return JsonNode.Parse(await client.GetStringAsync($"http://127.0.0.1:{_httpPort}{Prefix}/info.json"))!.AsObject();
        }

        public async ValueTask DisposeAsync()
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
            _storage.Dispose();
        }
    }

    /// <summary>
    /// An app on <c>TestServer</c> with the given configuration (section <c>TriggerGate</c>, HTTPS port 9443) and an app
    /// fallback, so a request the library does not answer is visible.
    /// </summary>
    private sealed class TestServerApp : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly TempDirectory _storage;

        private TestServerApp(WebApplication app, TempDirectory storage)
        {
            _app = app;
            _storage = storage;
            Client = app.GetTestClient();
        }

        public HttpClient Client { get; }

        public string StorageDirectory => _storage.Path;

        public IServiceProvider Services => _app.Services;

        public ITlsCaStatus Status => _app.Services.GetRequiredService<ITlsCaStatus>();

        public static async Task<TestServerApp> Start(Action<TlsCaOptions> configure, TestLogProvider logs, (string Key, string? Value)[]? configuration = null, TimeProvider? time = null)
        {
            TempDirectory storage = new();
            WebApplicationBuilder builder = WebApplication.CreateBuilder();
            _ = builder.Logging.ClearProviders();
            _ = builder.Logging.AddProvider(logs);
            _ = builder.Logging.SetMinimumLevel(LogLevel.Information);
            _ = builder.WebHost.UseTestServer();
            _ = builder.Configuration.AddInMemoryCollection((configuration ?? []).ToDictionary(pair => pair.Key, pair => pair.Value));
            if (time is not null)
            {
                _ = builder.Services.AddSingleton(time);
            }

            _ = builder.AddGameshowProTlsCa(ConfigureOptions);
            WebApplication app = builder.Build();
            _ = app.Use(SetRemoteAddress);
            _ = app.UseGameshowProTlsCa();
            _ = app.MapFallback("{**path}", context => context.Response.WriteAsync("fallback"));
            await app.StartAsync();
            return new(app, storage);

            void ConfigureOptions(TlsCaOptions options)
            {
                options.Product = "TriggerGate";
                options.AppLabel = "triggergate";
                options.StorageDirectory = storage.Path;
                options.HttpPort = 9090;
                options.HttpsPort = 9443;
                options.Version = "2.1.7";
                options.AdvertiseMdns = false;
                options.ConfigurationSection = "TriggerGate";
                options.CertificatePollInterval = TimeSpan.FromMilliseconds(100);
                configure(options);
            }

            Task SetRemoteAddress(HttpContext context, RequestDelegate next)
            {
                string? remote = context.Request.Headers[TestApp.RemoteHeader];
                context.Connection.RemoteIpAddress = remote is null ? IPAddress.Loopback : IPAddress.Parse(remote);
                return next(context);
            }
        }

        public Task<HttpResponseMessage> Get(string path) => Client.GetAsync(path);

        public Task<HttpResponseMessage> PostJson(string path, string? remote)
        {
            HttpRequestMessage request = new(HttpMethod.Post, path) { Content = new StringContent("{\"time\":1795300000}", Encoding.UTF8, "application/json") };
            if (remote is not null)
            {
                request.Headers.Add(TestApp.RemoteHeader, remote);
            }

            return Client.SendAsync(request);
        }

        public Task<HttpResponseMessage> Send(HttpMethod method, string path, HttpContent content) =>
            Client.SendAsync(new HttpRequestMessage(method, path) { Content = content });

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _app.StopAsync();
            await _app.DisposeAsync();
            _storage.Dispose();
        }
    }
}

/// <summary>
/// A throwaway PKI for the own-certificate tests: a root, optionally an intermediate, and a leaf for
/// <c>server.example.test</c>. Nothing is added to any certificate store; clients trust the root through
/// <see cref="X509ChainPolicy.CustomTrustStore"/>.
/// </summary>
internal sealed class TestChain : IDisposable
{
    private readonly AsymmetricAlgorithm _leafKey;

    private TestChain(X509Certificate2 root, X509Certificate2? intermediate, X509Certificate2 leaf, AsymmetricAlgorithm leafKey)
    {
        Root = root;
        Intermediate = intermediate;
        Leaf = leaf;
        _leafKey = leafKey;
    }

    public X509Certificate2 Root { get; }

    public X509Certificate2? Intermediate { get; }

    /// <summary>The leaf with its private key.</summary>
    public X509Certificate2 Leaf { get; }

    public static TestChain Create(bool withIntermediate, DateTimeOffset? notAfter = null, bool rsa = false)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 root = CaRequest("CN=TlsCa Test Root", rootKey, pathLength: 1).CreateSelfSigned(now.AddDays(-30), now.AddYears(10));
        X509Certificate2? intermediate = null;
        X509Certificate2 issuer = root;
        if (withIntermediate)
        {
            using ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateRequest request = CaRequest("CN=TlsCa Test Intermediate", intermediateKey, pathLength: 0);
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
            using X509Certificate2 signed = request.Create(root, now.AddDays(-20), now.AddYears(5), Serial());
            intermediate = signed.CopyWithPrivateKey(intermediateKey);
            issuer = intermediate;
        }

        AsymmetricAlgorithm leafKey = rsa ? RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest leafRequest = leafKey is RSA rsaKey
            ? new("CN=" + DnsNameOf(), rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            : new("CN=" + DnsNameOf(), (ECDsa)leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | (rsa ? X509KeyUsageFlags.KeyEncipherment : 0), true));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        SubjectAlternativeNameBuilder names = new();
        names.AddDnsName(DnsNameOf());
        leafRequest.CertificateExtensions.Add(names.Build());
        leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        // The issuers are ECDSA; an explicit generator lets them sign an RSA leaf too.
        using ECDsa issuerKey = issuer.GetECDsaPrivateKey()!;
        using X509Certificate2 leafSigned = leafRequest.Create(issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey), now.AddDays(-10), notAfter ?? now.AddYears(1), Serial());
        X509Certificate2 leaf = leafKey is RSA rsaLeafKey ? leafSigned.CopyWithPrivateKey(rsaLeafKey) : leafSigned.CopyWithPrivateKey((ECDsa)leafKey);

        // The test only ever needs the root's public certificate.
        X509Certificate2 rootPublic = X509CertificateLoader.LoadCertificate(root.RawData);
        root.Dispose();
        return new(rootPublic, intermediate, leaf, leafKey);

        static string DnsNameOf() => "server.example.test";
    }

    /// <summary>The leaf with its key and the intermediate (if any), as PKCS#12.</summary>
    public byte[] Pfx(string password)
    {
        // The intermediate travels without its private key, as in a real certificate file.
        using X509Certificate2? intermediate = Intermediate is null ? null : X509CertificateLoader.LoadCertificate(Intermediate.RawData);
        X509Certificate2Collection collection = [Leaf];
        if (intermediate is not null)
        {
            _ = collection.Add(intermediate);
        }

        return collection.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password);
    }

    public string WritePfx(string directory, string password)
    {
        _ = Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "server.pfx");
        File.WriteAllBytes(path, Pfx(password));
        return path;
    }

    /// <summary>The leaf then the intermediate (if any) in <c>server.pem</c>; the key there too, or in <c>server.key</c>, encrypted when a password is given.</summary>
    public (string Certificate, string? Key) WritePem(string directory, bool keyInCertificateFile, string? password)
    {
        _ = Directory.CreateDirectory(directory);
        StringBuilder certificates = new();
        _ = certificates.AppendLine(Leaf.ExportCertificatePem());
        if (Intermediate is not null)
        {
            _ = certificates.AppendLine(Intermediate.ExportCertificatePem());
        }

        string key = password is null
            ? _leafKey.ExportPkcs8PrivateKeyPem()
            : _leafKey.ExportEncryptedPkcs8PrivateKeyPem(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
        string certificatePath = Path.Combine(directory, "server.pem");
        if (keyInCertificateFile)
        {
            File.WriteAllText(certificatePath, certificates + key + "\n");
            return (certificatePath, null);
        }

        File.WriteAllText(certificatePath, certificates.ToString());
        string keyPath = Path.Combine(directory, "server.key");
        File.WriteAllText(keyPath, key + "\n");
        return (certificatePath, keyPath);
    }

    public void Dispose()
    {
        Root.Dispose();
        Intermediate?.Dispose();
        Leaf.Dispose();
        _leafKey.Dispose();
    }

    private static CertificateRequest CaRequest(string subject, ECDsa key, int pathLength)
    {
        CertificateRequest request = new(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }

    private static byte[] Serial()
    {
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] = (byte)((serial[0] & 0x7F) | 0x40);
        return serial;
    }
}
