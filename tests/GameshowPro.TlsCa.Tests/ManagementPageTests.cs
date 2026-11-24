namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// The shared management page (also embedded by the ESP32 firmware) words the Renew/Reset explanation and the refusal
/// for every gate kind a product reports in <c>info.json</c>: <c>loopback</c> (.NET), <c>button</c> and <c>boot</c> (ESP32).
/// </summary>
[TestClass]
public sealed class ManagementPageTests
{
    [TestMethod]
    [DataRow("loopback", "using a localhost address")]
    [DataRow("button", "within 60 seconds")]
    [DataRow("boot", "within 5 minutes")]
    public async Task Page_WordsEveryGateKind(string gate, string wording)
    {
        await using TestApp app = await TestApp.Start();

        string html = await app.Client.GetStringAsync("/.well-known/gameshowpro/");

        Assert.Contains($"gate === \"{gate}\"", html);
        Assert.Contains(wording, html);
    }

    [TestMethod]
    public async Task Page_ExplainsTheBootWindow()
    {
        await using TestApp app = await TestApp.Start();

        string html = await app.Client.GetStringAsync("/.well-known/gameshowpro/");

        Assert.Contains("Power-cycle the device, then press Renew or Reset here within 5 minutes.", html);
        Assert.Contains("Refused: power-cycle the device first, then try again within 5 minutes", html);
    }

    /// <summary>
    /// A 503 from <c>info.json</c> (no usable identity) is explained, and Reset stays on the page: with the JSON body the
    /// .NET library sends (product and gate kind), and with any other body, such as the ESP32 firmware's plain text.
    /// </summary>
    [TestMethod]
    public async Task Page_ExplainsAnUnusableIdentity_AndKeepsReset()
    {
        await using TestApp app = await TestApp.Start();

        string html = await app.Client.GetStringAsync("/.well-known/gameshowpro/");

        Assert.Contains("r.status === 503", html);
        Assert.Contains(".catch(function () { return {}; })", html);
        Assert.Contains("This device's certificate identity cannot be used", html);
        Assert.Contains("Reset replaces it with a new identity.", html);
        Assert.Contains("explainGate(j.gate, true);", html);
        Assert.Contains("Reset only works when this page is opened on the computer that runs the app, using a localhost address.", html);
        Assert.Contains("$(\"renew\").hidden = true;", html);
        Assert.Contains("$(\"manage\").hidden = false;", html);
    }

    [TestMethod]
    public async Task Page_OffersOtherComputersSecureAddressAndHttpSetupQrOnLocalhost()
    {
        await using TestApp app = await TestApp.Start();

        string html = await app.Client.GetStringAsync("/.well-known/gameshowpro/");

        Assert.Contains("id=\"other-computers\" hidden", html);
        Assert.Contains("id=\"share-address\"", html);
        Assert.Contains("id=\"copy-address\"", html);
        Assert.Contains("id=\"qr\"", html);
        Assert.Contains("id=\"fallback-addresses\"", html);
        Assert.Contains("box.hidden = !isLoopback();", html);
        Assert.Contains("$(\"share-address\").textContent = httpsUrl(i);", html);
        Assert.Contains("code.addData(setup);", html);
        Assert.Contains("\"fallbackAddresses\" in i", html);
        Assert.Contains("i.fallbackAddress ? [i.fallbackAddress] : []", html);
        Assert.Contains("item.appendChild(el(\"code\", address));", html);
        Assert.Contains("$(\"fallback-block\").hidden = !list.firstChild;", html);
        Assert.Contains("i.secureAddress ||", html);
        Assert.Contains("if (i.setupAddress) { return i.setupAddress; }", html);
        Assert.Contains("if (location.protocol !== \"http:\") { return null; }", html);
        Assert.Contains("qrcode-generator 2.0.4", html);
        Assert.Contains("MIT License", html);
    }

    [TestMethod]
    public async Task Page_ValidatesCarriedPath_AndOffersSessionHttpOnlyWhenEnabled()
    {
        await using TestApp app = await TestApp.Start();

        string html = await app.Client.GetStringAsync("/.well-known/gameshowpro/");

        Assert.Contains("new URLSearchParams(location.search).get(\"returnTo\")", html);
        Assert.Contains("target.origin === base.origin", html);
        Assert.Contains("target.origin === setup.origin", html);
        Assert.Contains("location.replace(destination);", html);
        Assert.Contains("id=\"http-fallback\" hidden", html);
        Assert.Contains("i.allowHttpFallback !== true", html);
        Assert.Contains("info.allowHttpFallback !== true", html);
        Assert.Contains("document.cookie = \"gsp-tlsca-http=1; Path=/; SameSite=Lax\"", html);
        Assert.Contains("location.assign(destination);", html);
        Assert.Contains("location.origin === new URL(url).origin", html);
    }
}
