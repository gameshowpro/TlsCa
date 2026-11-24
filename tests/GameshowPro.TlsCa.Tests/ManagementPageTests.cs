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
}
