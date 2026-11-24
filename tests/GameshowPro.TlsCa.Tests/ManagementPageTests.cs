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

    /// <summary>
    /// The own-certificate section is in the shared page but hidden until <c>info.json</c> says <c>certificateUpload: true</c>
    /// (the ESP32 firmware; this library never sends it), keeps the key input off plain HTTP, and needs no looser policy.
    /// </summary>
    [TestMethod]
    public async Task Page_OffersOwnCertificateOnlyWhenTheDeviceReportsTheCapability()
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.Client.GetAsync("/.well-known/gameshowpro/");
        string html = await response.Content.ReadAsStringAsync();

        Assert.Contains("id=\"own-cert\" hidden", html);
        Assert.Contains("box.hidden = !i || i.certificateUpload !== true;", html);
        Assert.Contains("$(\"own-cert\").hidden = true;", html);
        Assert.Contains("$(\"own-key\").disabled = !secure;", html);
        Assert.Contains("if (withKey && location.protocol !== \"https:\")", html);
        Assert.Contains("ownPost(\"certificate/remove\")", html);
        Assert.Contains("ownPost(\"certificate/request\")", html);
        Assert.Contains("certificate/request.csr", html);
        Assert.Contains("five minutes after the device powered up have passed", html);
        Assert.Contains("(status 415)", html);
        Assert.DoesNotContain("<script src", html);
        Assert.DoesNotContain("<link", html);
        string policy = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("script-src 'unsafe-inline'", policy);
        Assert.Contains("default-src 'none'", policy);
    }

    /// <summary>
    /// The page counts down the firmware's boot window (<c>gateSecondsRemaining</c>, absent from this library's
    /// <c>info.json</c>), words a 403 by its <c>reason</c> code, and keeps an HTTP page from forwarding to HTTPS while the
    /// certificate section is in use. The behavior itself is covered by <c>tests/management-page.test.cjs</c>.
    /// </summary>
    [TestMethod]
    public async Task Page_CountsDownTheGate_WordsRefusalsByReason_AndHoldsTheForwardWhileTheCertificateSectionIsUsed()
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.Client.GetAsync("/.well-known/gameshowpro/");
        string html = await response.Content.ReadAsStringAsync();

        Assert.Contains("i.gateSecondsRemaining", html);
        Assert.Contains("\"gate-closed\"", html);
        Assert.Contains("reason === \"host\"", html);
        Assert.Contains("reason === \"origin\"", html);
        Assert.Contains("$(\"own-cert\").addEventListener(\"focusin\", holdForward);", html);
        Assert.Contains("Recommended: create a signing request first.", html);
        Assert.Contains("RSA key", html);
        Assert.DoesNotContain("<script src", html);
    }

    [TestMethod]
    public async Task Page_ValidatesCarriedPath_AndOffersSessionFallbacksOnlyWhenEnabled()
    {
        await using TestApp app = await TestApp.Start();

        string html = await app.Client.GetStringAsync("/.well-known/gameshowpro/");

        Assert.Contains("new URLSearchParams(location.search).get(\"returnTo\")", html);
        Assert.Contains("target.origin === base.origin", html);
        Assert.Contains("target.origin === setup.origin", html);
        Assert.Contains("location.replace(destination);", html);
        Assert.Contains("id=\"http-fallback\" hidden", html);
        Assert.Contains("id=\"https-fallback\" hidden", html);
        Assert.Contains("i.allowHttpFallback !== true", html);
        Assert.Contains("i.allowHttpsFallback === true", html);
        Assert.Contains("info.allowHttpFallback !== true", html);
        Assert.Contains("info.allowHttpsFallback !== true", html);
        Assert.Contains("document.cookie = \"gsp-tlsca-http=1; Path=/; SameSite=Lax\"", html);
        Assert.Contains("document.cookie = \"gsp-tlsca-https=1; Path=/; SameSite=Lax; Secure\"", html);
        Assert.Contains("location.protocol !== \"https:\" || isLoopback()", html);
        Assert.Contains("base.hostname.toLowerCase() === new URL(httpsUrl(i)).hostname.toLowerCase()", html);
        Assert.Contains("!httpsEscapeReady", html);
        Assert.Contains("target.origin === base.origin", html);
        Assert.Contains("location.assign(destination);", html);
        Assert.Contains("location.origin === new URL(url).origin", html);
        Assert.Contains("tap Install anyway, then pick the downloaded file", html);
        Assert.Contains("do not open it from the download notification", html);
    }
}
