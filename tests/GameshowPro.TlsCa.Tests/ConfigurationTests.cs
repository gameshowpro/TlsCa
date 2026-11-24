namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// The two-call integration's configuration: the <c>ConfigurationSection</c> keys, external certificate detection, mode
/// resolution and its precedence, the default version, and <see cref="ITlsCaStatus"/>.
/// </summary>
[TestClass]
public sealed class ConfigurationTests
{
    private static IConfiguration Configuration(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => v.Value)).Build();

    private static WebApplicationBuilder Builder(params (string Key, string? Value)[] values)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.Logging.ClearProviders();
        _ = builder.WebHost.UseTestServer();
        _ = builder.Configuration.AddInMemoryCollection(values.ToDictionary(v => v.Key, v => v.Value));
        return builder;
    }

    private static void Configure(TlsCaOptions options, string storageDirectory)
    {
        options.Product = "TriggerGate";
        options.AppLabel = "triggergate";
        options.HttpPort = 9090;
        options.HttpsPort = 9190;
        options.StorageDirectory = storageDirectory;
        options.AdvertiseMdns = false;
        options.ConfigurationSection = "TriggerGate";
    }

    private static bool IsRegistered<T>(WebApplicationBuilder builder) => builder.Services.Any(d => d.ServiceType == typeof(T));

    // ConfigurationSection

    [TestMethod]
    public void Section_HttpsPort_OverridesTheOption()
    {
        TlsCaOptions options = new() { HttpsPort = 9190, ConfigurationSection = "TriggerGate" };
        TlsCaConfiguration.Apply(options, Configuration(("TriggerGate:HttpsPort", "19443")));
        Assert.AreEqual(19443, options.HttpsPort);
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("  ")]
    public void Section_BlankOrMissingHttpsPort_KeepsTheOption(string? value)
    {
        TlsCaOptions options = new() { HttpsPort = 9190, ConfigurationSection = "TriggerGate" };
        TlsCaConfiguration.Apply(options, Configuration(("TriggerGate:HttpsPort", value)));
        Assert.AreEqual(9190, options.HttpsPort);
    }

    [TestMethod]
    public void Section_HttpsPortZero_IsHttpsOff()
    {
        TlsCaOptions options = new() { HttpsPort = 9190, ConfigurationSection = "TriggerGate" };
        TlsCaConfiguration.Apply(options, Configuration(("TriggerGate:HttpsPort", "0")));
        Assert.AreEqual(0, options.HttpsPort);
    }

    [TestMethod]
    [DataRow("-1")]
    [DataRow("65536")]
    [DataRow("abc")]
    [DataRow("94 43")]
    public void Section_InvalidHttpsPort_ThrowsNamingTheKey(string value)
    {
        TlsCaOptions options = new() { HttpsPort = 9190, ConfigurationSection = "Soundling" };
        InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => TlsCaConfiguration.Apply(options, Configuration(("Soundling:HttpsPort", value))));
        Assert.Contains("Soundling:HttpsPort", exception.Message);
    }

    [TestMethod]
    public void Section_TlsStorageDirectory_OverridesTheOption_AndBlankIsIgnored()
    {
        TlsCaOptions options = new() { StorageDirectory = "default", ConfigurationSection = "TriggerGate" };
        TlsCaConfiguration.Apply(options, Configuration(("TriggerGate:TlsStorageDirectory", " ")));
        Assert.AreEqual("default", options.StorageDirectory);
        TlsCaConfiguration.Apply(options, Configuration(("TriggerGate:TlsStorageDirectory", @"C:\temp\tls")));
        Assert.AreEqual(@"C:\temp\tls", options.StorageDirectory);
    }

    [TestMethod]
    public void NoSection_ConfigurationIsNotRead()
    {
        TlsCaOptions options = new() { HttpsPort = 9190, StorageDirectory = "default" };
        TlsCaConfiguration.Apply(options, Configuration(("TriggerGate:HttpsPort", "abc"), ("TriggerGate:TlsStorageDirectory", "other")));
        Assert.AreEqual(9190, options.HttpsPort);
        Assert.AreEqual("default", options.StorageDirectory);
    }

    // External certificate

    [TestMethod]
    public void HasExternalCertificate_DefaultCertificatePath()
    {
        Assert.IsFalse(TlsCaConfiguration.HasExternalCertificate(Configuration()));
        Assert.IsTrue(TlsCaConfiguration.HasExternalCertificate(Configuration(("Kestrel:Certificates:Default:Path", "server.pfx"))));
        Assert.IsFalse(TlsCaConfiguration.HasExternalCertificate(Configuration(("Kestrel:Certificates:Default:Path", " "))));
    }

    [TestMethod]
    [DataRow("https://*:9443", true)]
    [DataRow("HTTPS://+:443", true)]
    [DataRow(" https://0.0.0.0:9443", true)]
    [DataRow("http://*:9090", false)]
    [DataRow("http://localhost:9090", false)]
    public void HasExternalCertificate_OnlyAnHttpsEndpointCounts(string url, bool expected) =>
        Assert.AreEqual(expected, TlsCaConfiguration.HasExternalCertificate(Configuration(("Kestrel:Endpoints:Main:Url", url))));

    [TestMethod]
    public void HasExternalCertificate_AnyHttpsEndpointAmongSeveral()
    {
        Assert.IsTrue(TlsCaConfiguration.HasExternalCertificate(Configuration(
            ("Kestrel:Endpoints:Http:Url", "http://*:9090"),
            ("Kestrel:Endpoints:Https:Url", "https://*:9443"))));
        Assert.IsFalse(TlsCaConfiguration.HasExternalCertificate(Configuration(
            ("Kestrel:Endpoints:Ui:Url", "http://*:80"),
            ("Kestrel:Endpoints:Hub:Url", "http://*:9090"),
            ("Kestrel:Endpoints:NoUrl:Protocols", "Http1"))));
    }

    // Mode resolution and AddGameshowProTlsCa

    [TestMethod]
    [DataRow("Kestrel:Certificates:Default:Path", "server.pfx", "Kestrel:Certificates:Default:Path")]
    [DataRow("Kestrel:Endpoints:Https:Url", "https://*:9443", "Kestrel:Endpoints:Https:Url")]
    public async Task Add_KestrelCertificate_IsKestrelMode_RegistersTheStatus_AndTouchesNoStorage(string key, string value, string setting)
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder((key, value));

        Assert.AreEqual(TlsCaMode.KestrelCertificate, builder.AddGameshowProTlsCa(options => Configure(options, directory.Path)));

        Assert.IsTrue(IsRegistered<ITlsCaStatus>(builder));
        Assert.IsFalse(IsRegistered<TlsIdentityManager>(builder));
        Assert.IsFalse(builder.Services.Any(d => d.ImplementationType == typeof(KestrelTlsConfigurator)), "The library adds no listener next to Kestrel's certificate.");
        await using WebApplication app = builder.Build();
        ITlsCaStatus status = app.Services.GetRequiredService<ITlsCaStatus>();
        Assert.AreEqual(TlsCaMode.KestrelCertificate, status.Mode);
        Assert.AreEqual(setting == "Kestrel:Endpoints:Https:Url" ? 9443 : 0, status.HttpsPort);
        Assert.IsNull(status.Problem);
        Assert.IsFalse(Directory.Exists(directory.Path));
    }

    [TestMethod]
    public void Add_PortZeroInConfiguration_IsOff_EvenWithBothCertificateSettings()
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder(
            ("TriggerGate:HttpsPort", "0"),
            ("TriggerGate:CertificatePath", "server.pfx"),
            ("Kestrel:Endpoints:Https:Url", "https://*:9443"));

        Assert.AreEqual(TlsCaMode.Off, builder.AddGameshowProTlsCa(options => Configure(options, directory.Path)));

        Assert.IsTrue(IsRegistered<ITlsCaStatus>(builder));
        Assert.IsFalse(IsRegistered<TlsIdentityManager>(builder));
        Assert.IsFalse(IsRegistered<OwnCertificateSource>(builder));
    }

    [TestMethod]
    public void Add_PortZeroInOptions_IsOff()
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder();

        Assert.AreEqual(TlsCaMode.Off, builder.AddGameshowProTlsCa(options =>
        {
            Configure(options, directory.Path);
            options.ConfigurationSection = null;
            options.HttpsPort = 0;
        }));
    }

    [TestMethod]
    public void Add_CertificatePath_WinsOverKestrel()
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder(("TriggerGate:CertificatePath", "server.pfx"), ("Kestrel:Endpoints:Https:Url", "https://*:9443"));

        Assert.AreEqual(TlsCaMode.OwnCertificate, builder.AddGameshowProTlsCa(options => Configure(options, directory.Path)));

        Assert.IsTrue(IsRegistered<OwnCertificateSource>(builder));
        Assert.IsFalse(IsRegistered<TlsIdentityManager>(builder));
    }

    [TestMethod]
    public void Add_NothingConfigured_IsBuiltInCa()
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder();

        Assert.AreEqual(TlsCaMode.BuiltInCa, builder.AddGameshowProTlsCa(options => Configure(options, directory.Path)));

        Assert.IsTrue(IsRegistered<TlsIdentityManager>(builder));
        Assert.IsFalse(IsRegistered<OwnCertificateSource>(builder));
    }

    [TestMethod]
    public void Add_CertificateKeysFromTheSection_OverrideTheOptions_AndRelativePathsUseTheContentRoot()
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder(
            ("TriggerGate:CertificatePath", "certs/server.pem"),
            ("TriggerGate:CertificateKeyPath", "certs/server.key"),
            ("TriggerGate:CertificatePassword", "from configuration"));
        TlsCaOptions? configured = null;

        Assert.AreEqual(TlsCaMode.OwnCertificate, builder.AddGameshowProTlsCa(options =>
        {
            Configure(options, directory.Path);
            options.CertificatePath = "ignored.pfx";
            options.CertificatePassword = "ignored";
            configured = options;
        }));

        Assert.IsNotNull(configured);
        string root = builder.Environment.ContentRootPath;
        Assert.AreEqual(Path.GetFullPath(Path.Combine(root, "certs", "server.pem")), configured.CertificatePath);
        Assert.AreEqual(Path.GetFullPath(Path.Combine(root, "certs", "server.key")), configured.CertificateKeyPath);
        Assert.AreEqual("from configuration", configured.CertificatePassword);
    }

    [TestMethod]
    public void Section_BlankCertificateKeys_AreIgnored()
    {
        TlsCaOptions options = new() { ConfigurationSection = "Soundling", CertificatePath = "a.pfx", CertificatePassword = "p" };
        TlsCaConfiguration.Apply(options, Configuration(("Soundling:CertificatePath", " "), ("Soundling:CertificatePassword", "")));
        Assert.AreEqual("a.pfx", options.CertificatePath);
        Assert.AreEqual("p", options.CertificatePassword);
    }

    [TestMethod]
    public void Add_KeyPathWithoutCertificatePath_Throws()
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder(("TriggerGate:CertificateKeyPath", "server.key"));
        _ = Assert.ThrowsExactly<ArgumentException>(() => builder.AddGameshowProTlsCa(options => Configure(options, directory.Path)));
    }

    [TestMethod]
    [DataRow("70000")]
    [DataRow("not a number")]
    public void Add_InvalidPort_Throws_WhateverElseIsConfigured(string port)
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder(("TriggerGate:HttpsPort", port), ("Kestrel:Endpoints:Https:Url", "https://*:9443"));
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => builder.AddGameshowProTlsCa(options => Configure(options, directory.Path)));
    }

    [TestMethod]
    public async Task Add_HttpOnlyKestrelEndpoints_IsBuiltInCa_WithTheEffectiveValuesOnTheOptions()
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder(
            ("Kestrel:Endpoints:Http:Url", "http://*:9090"),
            ("TriggerGate:HttpsPort", "19443"),
            ("TriggerGate:TlsStorageDirectory", directory.Path));
        TlsCaOptions? configured = null;

        Assert.AreEqual(TlsCaMode.BuiltInCa, builder.AddGameshowProTlsCa(options =>
        {
            Configure(options, "overridden by configuration");
            configured = options;
        }));

        Assert.IsNotNull(configured);
        Assert.AreEqual(19443, configured.HttpsPort);
        Assert.AreEqual(directory.Path, configured.StorageDirectory);
        await using WebApplication app = builder.Build();
        Assert.AreSame(configured, app.Services.GetRequiredService<TlsCaOptions>());
        Assert.AreEqual(19443, app.Services.GetRequiredService<ITlsCaStatus>().HttpsPort);
        Assert.AreEqual(TlsCaMode.BuiltInCa, app.Services.GetRequiredService<ITlsCaStatus>().Mode);
        Assert.IsTrue(File.Exists(directory.IdentityFile));
    }

    [TestMethod]
    public async Task Add_AppliesTheSectionToo()
    {
        using TempDirectory directory = new();
        WebApplicationBuilder builder = Builder(("TriggerGate:HttpsPort", "19443"), ("TriggerGate:TlsStorageDirectory", directory.Path));
        _ = builder.AddGameshowProTlsCa(options => Configure(options, "overridden by configuration"));
        await using WebApplication app = builder.Build();

        TlsCaOptions options = app.Services.GetRequiredService<TlsCaOptions>();

        Assert.AreEqual(19443, options.HttpsPort);
        Assert.AreEqual(directory.Path, options.StorageDirectory);
    }

    // Version

    [TestMethod]
    public void DefaultVersion_IsTheInformationalVersionWithoutMetadata()
    {
        Assembly assembly = typeof(TlsCaOptions).Assembly;
        string informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;

        string? version = TlsCaConfiguration.DefaultVersion(assembly);

        Assert.IsNotNull(version);
        Assert.DoesNotContain("+", version);
        Assert.AreEqual(informational.Split('+')[0], version);
        Assert.IsNull(TlsCaConfiguration.DefaultVersion(null));
    }

    [TestMethod]
    public async Task Version_NullUsesTheEntryAssembly_AndAnExplicitVersionIsKept()
    {
        await using (TestApp app = await TestApp.Start(options => options.Version = null))
        {
            JsonObject info = JsonNode.Parse(await app.Client.GetStringAsync("/.well-known/gameshowpro/info.json"))!.AsObject();
            Assert.AreEqual(TlsCaConfiguration.DefaultVersion(Assembly.GetEntryAssembly()), (string?)info["version"]);
        }

        await using (TestApp app = await TestApp.Start(options => options.Version = "3.4.5"))
        {
            JsonObject info = JsonNode.Parse(await app.Client.GetStringAsync("/.well-known/gameshowpro/info.json"))!.AsObject();
            Assert.AreEqual("3.4.5", (string?)info["version"]);
        }
    }

    // ITlsCaStatus

    [TestMethod]
    public async Task Status_ReportsTheIdentity()
    {
        await using TestApp app = await TestApp.Start();
        ITlsCaStatus status = app.App.Services.GetRequiredService<ITlsCaStatus>();
        TlsIdentity identity = app.Manager.Current;

        Assert.AreEqual(identity.MdnsName, status.MdnsName);
        Assert.AreEqual(9443, status.HttpsPort);
        Assert.AreEqual(identity.CaFingerprintSha256, status.CaFingerprintSha256);
        Assert.IsFalse(status.NameConflict);
        Assert.IsNull(status.NameMismatch);
        Assert.AreSame(app.App.Services.GetRequiredService<TlsCaStatus>(), status);
    }

    [TestMethod]
    public async Task Status_ChangedIsRaisedOnResetAndOnANameConflictChange()
    {
        await using TestApp app = await TestApp.Start();
        ITlsCaStatus status = app.App.Services.GetRequiredService<ITlsCaStatus>();
        int raised = 0;
        status.Changed += (_, _) => Interlocked.Increment(ref raised);
        string before = status.CaFingerprintSha256;

        _ = await app.Manager.ResetIdentity();
        Assert.AreEqual(1, raised);
        Assert.AreNotEqual(before, status.CaFingerprintSha256);

        TlsCaStatus internalStatus = app.App.Services.GetRequiredService<TlsCaStatus>();
        internalStatus.NameConflict = true;
        Assert.AreEqual(2, raised);
        Assert.IsTrue(status.NameConflict);
        internalStatus.NameConflict = true;
        Assert.AreEqual(2, raised, "Setting the same value is not a change.");
        internalStatus.NameConflict = false;
        Assert.AreEqual(3, raised);
    }

    [TestMethod]
    public async Task Status_AThrowingHandler_DoesNotBreakARenewal()
    {
        await using TestApp app = await TestApp.Start();
        ITlsCaStatus status = app.App.Services.GetRequiredService<ITlsCaStatus>();
        bool second = false;
        status.Changed += (_, _) => throw new InvalidOperationException("app handler");
        status.Changed += (_, _) => second = true;
        string before = app.Manager.Current.LeafFingerprintSha256;

        using HttpResponseMessage response = await app.PostJson("/.well-known/gameshowpro/renew");

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreNotEqual(before, app.Manager.Current.LeafFingerprintSha256);
        Assert.IsTrue(second);
    }
}
