namespace GameshowPro.TlsCa.Tests;

[TestClass]
public sealed class AddressTests
{
    private static readonly string[] s_localIpv4 = ["http://10.1.2.3:9090/"];
    private static readonly string[] s_localIpv6 = ["http://[fd00::12]:9090/"];
    private static readonly string[] s_lanAddresses = ["http://10.183.49.101:9090/", "http://10.183.49.102:9090/"];
    private static readonly string[] s_scopedAddresses = ["http://10.147.20.159:9090/", "http://[fd00::12]:9090/"];
    private static readonly string[] s_scopedHttpsAddresses = ["https://10.147.20.159:9190/", "https://[fd00::12]:9190/"];

    [TestMethod]
    public async Task BuiltInStatusAndInfo_ProvideReadyMadeAddresses()
    {
        await using TestApp app = await TestApp.Start();
        TlsIdentity identity = app.Manager.Current;

        Assert.AreEqual($"https://{identity.MdnsName}:9443/", app.Status.SecureAddress);
        Assert.AreEqual($"http://{identity.MdnsName}:9090/.well-known/gameshowpro/", app.Status.SetupAddress);

        using HttpResponseMessage response = await app.Get("/.well-known/gameshowpro/info.json");
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.AreEqual(app.Status.SecureAddress, (string?)info["secureAddress"]);
        Assert.AreEqual(app.Status.SetupAddress, (string?)info["setupAddress"]);
        Assert.AreEqual(true, (bool?)info["allowHttpFallback"]);
        Assert.AreEqual(true, (bool?)info["allowHttpsFallback"]);
    }

    [TestMethod]
    public async Task DisabledHttpAndFallback_HaveNoSetupAddress()
    {
        await using TestApp app = await TestApp.Start(ConfigureOptions);

        Assert.IsNull(app.Status.SetupAddress);
        using HttpResponseMessage response = await app.Get("/.well-known/gameshowpro/info.json");
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.IsNull(info["setupAddress"]);
        Assert.IsNull(info["fallbackAddress"]);
        Assert.IsEmpty(info["fallbackAddresses"]!.AsArray());
        Assert.AreEqual(false, (bool?)info["allowHttpFallback"]);
        Assert.AreEqual(true, (bool?)info["allowHttpsFallback"]);

        static void ConfigureOptions(TlsCaOptions options)
        {
            options.HttpPort = 0;
            options.AllowHttpFallback = false;
            options.MdnsScopes = [];
        }
    }

    [TestMethod]
    [DataRow(true, 9443, "http://10.147.20.159:9090/")]
    [DataRow(false, 9443, "https://10.147.20.159:9443/")]
    [DataRow(false, 0, "http://10.147.20.159:9090/")]
    public async Task FallbackAddress_UsesHttpsOnlyWhenHttpFallbackIsOffAndHttpsIsOn(
        bool allowHttpFallback, int httpsPort, string expected)
    {
        await using TestApp app = await TestApp.Start(ConfigureOptions);
        using HttpResponseMessage response = await app.Get("/.well-known/gameshowpro/info.json");
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.AreEqual(expected, (string?)info["fallbackAddress"]);
        CollectionAssert.AreEqual(new[] { expected }, info["fallbackAddresses"]!.AsArray().Select(static address => address!.GetValue<string>()).ToArray());

        void ConfigureOptions(TlsCaOptions options)
        {
            options.AllowHttpFallback = allowHttpFallback;
            options.HttpsPort = httpsPort;
            options.MdnsScopes = [new TlsCaMdnsScope("vpn", IPAddress.Parse("10.147.20.159"))];
        }
    }

    [TestMethod]
    public async Task HttpsFallbackOption_IsReportedIndependently()
    {
        await using TestApp app = await TestApp.Start(static options =>
        {
            options.AllowHttpFallback = false;
            options.AllowHttpsFallback = false;
        });
        using HttpResponseMessage response = await app.Get("/.well-known/gameshowpro/info.json");
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.AreEqual(false, (bool?)info["allowHttpFallback"]);
        Assert.AreEqual(false, (bool?)info["allowHttpsFallback"]);
    }

    [TestMethod]
    public async Task SetupAddress_IsManagementPage_WhenHttpRootRedirectIsDisabled()
    {
        await using TestApp app = await TestApp.Start(static options => options.RedirectHttpRoot = false);
        string expected = $"http://{app.Manager.Current.MdnsName}:9090/.well-known/gameshowpro/";

        Assert.AreEqual(expected, app.Status.SetupAddress);
        using HttpResponseMessage response = await app.Get("/.well-known/gameshowpro/info.json");
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.AreEqual(expected, (string?)info["setupAddress"]);
    }

    [TestMethod]
    public async Task UnavailableIdentity_HasNoSecureOrSetupAddress()
    {
        await using TestApp app = await TestApp.Start(prepareStorage: path => _ = BrokenStorage.WriteCorruptIdentity(path));

        Assert.IsNull(app.Status.SecureAddress);
        Assert.IsNull(app.Status.SetupAddress);
        using HttpResponseMessage response = await app.Get("/.well-known/gameshowpro/info.json");
        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.IsNull(info["secureAddress"]);
        Assert.IsNull(info["setupAddress"]);
        Assert.AreEqual(true, (bool?)info["allowHttpsFallback"]);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    public async Task InfoJson_ExplicitScopesControlFallbackAddressCardinality(int count)
    {
        await using TestApp app = await TestApp.Start(ConfigureOptions);
        using HttpResponseMessage response = await app.Get("/.well-known/gameshowpro/info.json");
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        string[] expected = s_scopedAddresses[..count];
        string[] actual = [.. info["fallbackAddresses"]!.AsArray().Select(static address => address!.GetValue<string>())];

        CollectionAssert.AreEqual(expected, actual);
        Assert.AreEqual(count == 1 ? expected[0] : null, (string?)info["fallbackAddress"]);

        void ConfigureOptions(TlsCaOptions options)
        {
            TlsCaMdnsScope[] scopes =
            [
                new("vpn", IPAddress.Parse("10.147.20.159")),
                new("ipv6", IPAddress.Parse("fd00::12")),
            ];
            options.MdnsScopes = scopes.Take(count).ToArray();
        }
    }

    [TestMethod]
    public void FallbackAddresses_PreferRequestLocalAddress()
    {
        AddressSuggestions.NetworkSnapshot network = new("Ethernet", "Realtek controller", NetworkInterfaceType.Ethernet,
            true, true, [IPAddress.Parse("192.168.1.40"), IPAddress.Parse("10.0.0.4")]);

        CollectionAssert.AreEqual(s_localIpv4, AddressSuggestions.FallbackAddresses(IPAddress.Parse("10.1.2.3"), null, [network], 9090));
        CollectionAssert.AreEqual(s_localIpv6, AddressSuggestions.FallbackAddresses(IPAddress.Parse("fd00::12"), null, [network], 9090));
    }

    [TestMethod]
    public void FallbackAddresses_EnumeratePhysicalLanAndExcludeVirtualAdapters()
    {
        AddressSuggestions.NetworkSnapshot[] networks =
        [
            new("ZeroTier One", "ZeroTier Virtual Port", NetworkInterfaceType.Ethernet, true, true, [IPAddress.Parse("10.147.20.159")]),
            new("Ethernet 6", "Realtek Gaming 2.5GbE Family Controller", NetworkInterfaceType.Ethernet, true, true, [IPAddress.Parse("10.183.49.101"), IPAddress.Parse("10.183.49.102")]),
            new("No gateway", "Realtek", NetworkInterfaceType.Ethernet, true, false, [IPAddress.Parse("192.168.2.5")]),
            new("Loopback", "Loopback", NetworkInterfaceType.Loopback, true, true, [IPAddress.Loopback]),
            new("Down Wi-Fi", "Wireless", NetworkInterfaceType.Wireless80211, false, true, [IPAddress.Parse("192.168.1.10")]),
        ];

        CollectionAssert.AreEqual(s_lanAddresses,
            AddressSuggestions.FallbackAddresses(IPAddress.Loopback, null, networks, 9090));
        Assert.IsEmpty(AddressSuggestions.FallbackAddresses(IPAddress.Loopback, null, networks, 0));
    }

    [TestMethod]
    public void FallbackAddresses_ExplicitScopesAreAuthoritative()
    {
        AddressSuggestions.NetworkSnapshot real = new("Ethernet", "Realtek", NetworkInterfaceType.Ethernet, true, true, [IPAddress.Parse("10.183.49.101")]);
        TlsCaMdnsScope[] scopes =
        [
            new("vpn", IPAddress.Parse("10.147.20.159")),
            new("vpn", IPAddress.Parse("10.147.20.159")),
            new("ipv6", IPAddress.Parse("fd00::12")),
        ];

        CollectionAssert.AreEqual(s_scopedAddresses,
            AddressSuggestions.FallbackAddresses(IPAddress.Parse("10.183.49.101"), scopes, [real], 9090));
        Assert.IsEmpty(AddressSuggestions.FallbackAddresses(IPAddress.Loopback, [], [real], 9090));
        CollectionAssert.AreEqual(
            s_scopedHttpsAddresses,
            AddressSuggestions.FallbackAddresses(IPAddress.Parse("10.183.49.101"), scopes, [real], 9190, https: true));
    }
    [TestMethod]
    public async Task InfoJson_MultiAddressScopeSuggestsEveryUsableAddress()
    {
        await using TestApp app = await TestApp.Start(static options => options.MdnsScopes =
        [
            new TlsCaMdnsScope("nic-a", (IReadOnlyCollection<IPAddress>)[
                IPAddress.Parse("fd00::12"), IPAddress.Parse("10.147.20.159"),
                IPAddress.Parse("fe80::12%4"), IPAddress.Loopback]),
        ]);

        using HttpResponseMessage response = await app.Get("/.well-known/gameshowpro/info.json");
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        CollectionAssert.AreEqual(s_scopedAddresses,
            info["fallbackAddresses"]!.AsArray().Select(static item => item!.GetValue<string>()).ToArray());
        Assert.IsNull(info["fallbackAddress"]);
    }
}
