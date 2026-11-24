namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Acceptance test 9: every endpoint's status, content type and cache header; no response contains key material;
/// the POSTs refuse non-JSON, non-loopback, foreign Origin and foreign Host; a renew keeps the CA and a reset changes it.
/// </summary>
[TestClass]
public sealed class HttpSurfaceTests
{
    private const string Prefix = "/.well-known/gameshowpro";

    /// <summary>The device name comes from the machine's own host name, so the data rows use a placeholder for it.</summary>
    private static string Fill(string value, TlsIdentity identity) => value.Replace("{name}", identity.Name, StringComparison.Ordinal);

    private static readonly string[] s_infoFields =
    [
        "product", "name", "mdnsName", "httpsPort", "caFingerprintSha256", "previousCaFingerprintSha256", "leafNotBefore",
        "leafNotAfter", "caNotAfter", "version", "gate", "nameConflict", "nameMismatch", "certificateSource",
    ];

    [TestMethod]
    [DataRow("/ca.crt", "application/x-x509-ca-cert")]
    [DataRow("/ca.pem", "application/x-pem-file")]
    [DataRow("/ca.mobileconfig", "application/x-apple-aspen-config")]
    [DataRow("/info.json", "application/json")]
    [DataRow("/", "text/html")]
    public async Task Get_EveryEndpoint_HasStatusContentTypeAndNoStore(string path, string contentType)
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.Get(Prefix + path);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(contentType, response.Content.Headers.ContentType?.MediaType);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        Assert.IsFalse(response.Headers.Contains("Set-Cookie"));
    }

    [TestMethod]
    public async Task Get_PageWithAndWithoutTrailingSlash_IsServed()
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage withSlash = await app.Get(Prefix + "/");
        using HttpResponseMessage withoutSlash = await app.Get(Prefix);

        Assert.AreEqual(HttpStatusCode.OK, withSlash.StatusCode);
        Assert.AreEqual(HttpStatusCode.OK, withoutSlash.StatusCode);
        string html = await withSlash.Content.ReadAsStringAsync();
        Assert.StartsWith("<!doctype html>", html);
        Assert.IsTrue(withSlash.Headers.Contains("Content-Security-Policy"));
        Assert.Contains("frame-ancestors 'none'", withSlash.Headers.GetValues("Content-Security-Policy").Single());
        Assert.AreEqual(html, await withoutSlash.Content.ReadAsStringAsync());
    }

    [TestMethod]
    public async Task Head_OnReadEndpoints_IsAnswered()
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.Send(HttpMethod.Head, Prefix + "/info.json");

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
    }

    [TestMethod]
    public async Task Get_UnknownPathAndPostToReadEndpoint_AreNotServed()
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage unknown = await app.Get(Prefix + "/nothing");
        using HttpResponseMessage post = await app.PostJson(Prefix + "/info.json");

        Assert.AreEqual(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.AreEqual(HttpStatusCode.MethodNotAllowed, post.StatusCode);
        Assert.AreEqual("no-store", post.Headers.CacheControl?.ToString());
    }

    [TestMethod]
    public async Task CaCrt_IsTheDerCertificate_AndCaPemIsItsPem()
    {
        await using TestApp app = await TestApp.Start();
        TlsIdentity identity = app.Manager.Current;

        byte[] der = await app.Client.GetByteArrayAsync(Prefix + "/ca.crt");
        string pem = await app.Client.GetStringAsync(Prefix + "/ca.pem");

        CollectionAssert.AreEqual(identity.CaCertificateDer.ToArray(), der);
        using X509Certificate2 fromDer = X509CertificateLoader.LoadCertificate(der);
        Assert.AreEqual(identity.CaFingerprintSha256, Fingerprint.Sha256(fromDer));
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", pem);
        PemFields fields = PemEncoding.Find(pem);
        CollectionAssert.AreEqual(der, Convert.FromBase64String(pem[fields.Base64Data]));
        Assert.IsFalse(pem.Contains("PRIVATE", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task InfoJson_HasExactlyTheSharedFieldsAndAllowsAnyOrigin()
    {
        await using TestApp app = await TestApp.Start();
        TlsIdentity identity = app.Manager.Current;

        using HttpResponseMessage response = await app.Get(Prefix + "/info.json", request => request.Headers.Add("Origin", "https://elsewhere.example"));
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();

        Assert.AreEqual("*", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        CollectionAssert.AreEquivalent(s_infoFields, info.Select(pair => pair.Key).ToArray());
        Assert.AreEqual("TriggerGate", (string?)info["product"]);
        Assert.AreEqual(identity.Name, (string?)info["name"]);
        Assert.AreEqual(identity.Name + ".local", (string?)info["mdnsName"]);
        Assert.AreEqual(9443, (int?)info["httpsPort"]);
        Assert.AreEqual(identity.CaFingerprintSha256, (string?)info["caFingerprintSha256"]);
        Assert.IsNull(info["previousCaFingerprintSha256"]);
        Assert.AreEqual(identity.LeafNotBefore.ToUnixTimeSeconds(), (long?)info["leafNotBefore"]);
        Assert.AreEqual(identity.LeafNotAfter.ToUnixTimeSeconds(), (long?)info["leafNotAfter"]);
        Assert.AreEqual(identity.CaNotAfter.ToUnixTimeSeconds(), (long?)info["caNotAfter"]);
        Assert.AreEqual("2.1.7", (string?)info["version"]);
        Assert.AreEqual("loopback", (string?)info["gate"]);
        Assert.AreEqual(false, (bool?)info["nameConflict"]);
        Assert.IsNull(info["nameMismatch"]);
        Assert.AreEqual("ca", (string?)info["certificateSource"]);
    }

    [TestMethod]
    public async Task OtherEndpoints_DoNotAllowAnyOrigin()
    {
        await using TestApp app = await TestApp.Start();

        foreach (string path in new[] { "/ca.crt", "/ca.pem", "/ca.mobileconfig", "/" })
        {
            using HttpResponseMessage response = await app.Get(Prefix + path);
            Assert.IsFalse(response.Headers.Contains("Access-Control-Allow-Origin"), path);
        }
    }

    [TestMethod]
    public async Task InfoJson_ReportsNameConflict()
    {
        await using TestApp app = await TestApp.Start();
        app.App.Services.GetRequiredService<TlsCaStatus>().NameConflict = true;

        JsonObject info = JsonNode.Parse(await app.Client.GetStringAsync(Prefix + "/info.json"))!.AsObject();

        Assert.AreEqual(true, (bool?)info["nameConflict"]);
    }

    [TestMethod]
    public async Task InfoJson_UsesTheGatesKind()
    {
        await using TestApp app = await TestApp.Start(options => options.Gate = new DelegateGate("button", _ => true));

        JsonObject info = JsonNode.Parse(await app.Client.GetStringAsync(Prefix + "/info.json"))!.AsObject();

        Assert.AreEqual("button", (string?)info["gate"]);
    }

    [TestMethod]
    [DataRow("renew")]
    [DataRow("reset")]
    public async Task Post_FromLoopbackWithJson_IsAllowed_AndAnswersWithInfo(string action)
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.PostJson($"{Prefix}/{action}");

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        Assert.IsFalse(response.Headers.Contains("Access-Control-Allow-Origin"));
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.AreEqual(app.Manager.Current.CaFingerprintSha256, (string?)info["caFingerprintSha256"]);
    }

    [TestMethod]
    public async Task Renew_KeepsTheCa_AndReplacesTheLeaf()
    {
        await using TestApp app = await TestApp.Start();
        TlsIdentity before = app.Manager.Current;

        using HttpResponseMessage response = await app.PostJson(Prefix + "/renew");

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        TlsIdentity after = app.Manager.Current;
        Assert.AreEqual(before.CaFingerprintSha256, after.CaFingerprintSha256);
        Assert.AreNotEqual(before.LeafFingerprintSha256, after.LeafFingerprintSha256);
        Assert.IsNull(after.PreviousCaFingerprintSha256);
    }

    [TestMethod]
    public async Task Reset_ChangesTheFingerprint_AndRecordsThePreviousOne()
    {
        await using TestApp app = await TestApp.Start();
        TlsIdentity before = app.Manager.Current;

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset");
        JsonObject info = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        TlsIdentity after = app.Manager.Current;
        Assert.AreNotEqual(before.CaFingerprintSha256, after.CaFingerprintSha256);
        Assert.AreEqual(after.CaFingerprintSha256, (string?)info["caFingerprintSha256"]);
        Assert.AreEqual(before.CaFingerprintSha256, (string?)info["previousCaFingerprintSha256"]);
        Assert.AreEqual(after.CaFingerprintSha256, Fingerprint.Sha256(await app.Client.GetByteArrayAsync(Prefix + "/ca.crt")));
    }

    [TestMethod]
    [DataRow("renew")]
    [DataRow("reset")]
    public async Task Post_WithoutJsonContentType_Is415_AndChangesNothing(string action)
    {
        await using TestApp app = await TestApp.Start();
        string before = app.Manager.Current.LeafFingerprintSha256;

        foreach (string contentType in new[] { "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/jsonx", "application/vnd.api+json" })
        {
            using HttpResponseMessage response = await app.PostJson($"{Prefix}/{action}", request => request.Content = Body(contentType));
            Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, response.StatusCode, contentType);
            Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        }

        using HttpResponseMessage noBody = await app.Send(HttpMethod.Post, $"{Prefix}/{action}");
        Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, noBody.StatusCode);
        Assert.AreEqual(before, app.Manager.Current.LeafFingerprintSha256);
    }

    [TestMethod]
    public async Task Post_JsonWithACharsetParameter_IsAccepted()
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.PostJson(Prefix + "/renew", request => request.Content = Body("application/json; charset=utf-8"));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [TestMethod]
    [DataRow("renew", "192.168.1.50")]
    [DataRow("reset", "192.168.1.50")]
    [DataRow("renew", "none")]
    [DataRow("reset", "2001:db8::1")]
    [DataRow("renew", "::ffff:192.168.1.50")]
    public async Task Post_FromANonLoopbackRemote_Is403_AndChangesNothing(string action, string remote)
    {
        await using TestApp app = await TestApp.Start();
        TlsIdentity before = app.Manager.Current;

        using HttpResponseMessage response = await app.PostJson($"{Prefix}/{action}", request => request.Headers.Add(TestApp.RemoteHeader, remote));

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        Assert.AreSame(before, app.Manager.Current);
    }

    [TestMethod]
    [DataRow("127.0.0.1")]
    [DataRow("127.0.0.2")]
    [DataRow("::1")]
    [DataRow("::ffff:127.0.0.1")]
    public async Task Post_FromAnyLoopbackRemote_IsAllowed(string remote)
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.PostJson(Prefix + "/renew", request => request.Headers.Add(TestApp.RemoteHeader, remote));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [TestMethod]
    [DataRow("X-Forwarded-For", "127.0.0.1")]
    [DataRow("X-Forwarded-For", "::1")]
    [DataRow("X-Forwarded-Host", "localhost")]
    [DataRow("X-Forwarded-Proto", "https")]
    [DataRow("X-Real-IP", "127.0.0.1")]
    [DataRow("Forwarded", "for=127.0.0.1;host=localhost")]
    public async Task Post_ForwardingHeadersFromANonLoopbackRemote_DoNotMakeItLocal(string header, string value)
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset", AddForwardingHeaders);

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);

        void AddForwardingHeaders(HttpRequestMessage request)
        {
            request.Headers.Add(TestApp.RemoteHeader, "192.168.1.50");
            request.Headers.Add(header, value);
        }
    }

    [TestMethod]
    public async Task Post_ForwardingHeadersFromALoopbackRemote_AreIgnored()
    {
        await using TestApp app = await TestApp.Start();

        // A forwarded address does not make a loopback connection less local, and a forwarded host does not change Host.
        using HttpResponseMessage response = await app.PostJson(Prefix + "/renew", request => request.Headers.Add("X-Forwarded-For", "192.168.1.50"));
        using HttpResponseMessage foreignHost = await app.PostJson(Prefix + "/renew", SetForeignHost);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(HttpStatusCode.Forbidden, foreignHost.StatusCode);

        static void SetForeignHost(HttpRequestMessage request)
        {
            request.Headers.Host = "evil.example";
            request.Headers.Add("X-Forwarded-Host", "localhost");
        }
    }

    [TestMethod]
    [DataRow("https://evil.example")]
    [DataRow("http://evil.example")]
    [DataRow("http://localhost:1234")]
    [DataRow("http://127.0.0.1")]
    [DataRow("null")]
    [DataRow("not a url")]
    public async Task Post_WithAForeignOrigin_Is403(string origin)
    {
        await using TestApp app = await TestApp.Start();
        TlsIdentity before = app.Manager.Current;

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset", request => _ = request.Headers.TryAddWithoutValidation("Origin", origin));

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.AreSame(before, app.Manager.Current);
    }

    [TestMethod]
    [DataRow("http://localhost", "localhost")]
    [DataRow("http://localhost:80", "localhost")]
    [DataRow("http://localhost:9090", "localhost:9090")]
    [DataRow("http://LOCALHOST:9090", "localhost:9090")]
    [DataRow("http://127.0.0.1:9090", "127.0.0.1:9090")]
    [DataRow("http://[::1]:9090", "[::1]:9090")]
    [DataRow("http://{name}.local:9090", "{name}.local:9090")]
    public async Task Post_WithAnOriginEqualToTheHost_IsAllowed(string origin, string host)
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.PostJson(Prefix + "/renew", SetMatchingOrigin);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);

        void SetMatchingOrigin(HttpRequestMessage request)
        {
            request.Headers.Host = Fill(host, app.Manager.Current);
            _ = request.Headers.TryAddWithoutValidation("Origin", Fill(origin, app.Manager.Current));
        }
    }

    [TestMethod]
    public async Task Post_WithTwoOriginHeaders_Is403()
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.PostJson(Prefix + "/renew", AddTwoOrigins);

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);

        static void AddTwoOrigins(HttpRequestMessage request)
        {
            _ = request.Headers.TryAddWithoutValidation("Origin", "http://localhost");
            _ = request.Headers.TryAddWithoutValidation("Origin", "http://evil.example");
        }
    }

    [TestMethod]
    [DataRow("evil.example")]
    [DataRow("evil.example:9090")]
    [DataRow("192.168.1.10:9090")]
    [DataRow("other-pc-triggergate.local")]
    [DataRow("{name}.local.evil.example")]
    [DataRow("localhost.evil.example")]
    public async Task Post_WithAForeignHost_Is403(string host)
    {
        await using TestApp app = await TestApp.Start();
        TlsIdentity before = app.Manager.Current;

        using HttpResponseMessage response = await app.PostJson(Prefix + "/reset", request => request.Headers.Host = Fill(host, app.Manager.Current));

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.AreSame(before, app.Manager.Current);
    }

    [TestMethod]
    [DataRow("localhost")]
    [DataRow("localhost:9090")]
    [DataRow("127.0.0.1:9090")]
    [DataRow("[::1]:9090")]
    [DataRow("{name}.local")]
    [DataRow("{name}.LOCAL:9443")]
    public async Task Post_WithAnOwnHost_IsAllowed(string host)
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.PostJson(Prefix + "/renew", request => request.Headers.Host = Fill(host, app.Manager.Current));

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [TestMethod]
    [DataRow("renew")]
    [DataRow("reset")]
    [DataRow("info.json")]
    [DataRow("ca.crt")]
    [DataRow("")]
    public async Task Options_Preflight_GrantsNothing(string path)
    {
        await using TestApp app = await TestApp.Start();

        using HttpResponseMessage response = await app.Send(HttpMethod.Options, $"{Prefix}/{path}", AddPreflightHeaders);

        Assert.IsFalse(response.IsSuccessStatusCode, response.StatusCode.ToString());
        Assert.AreEqual("no-store", response.Headers.CacheControl?.ToString());
        foreach (string header in new[] { "Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Allow-Credentials" })
        {
            Assert.IsFalse(response.Headers.Contains(header), header);
        }

        static void AddPreflightHeaders(HttpRequestMessage request)
        {
            request.Headers.Add("Origin", "https://evil.example");
            request.Headers.Add("Access-Control-Request-Method", "POST");
            request.Headers.Add("Access-Control-Request-Headers", "content-type");
        }
    }

    [TestMethod]
    public async Task CustomGate_DecidesPosts()
    {
        bool allow = false;
        await using TestApp app = await TestApp.Start(options => options.Gate = new DelegateGate("button", _ => allow));
        TlsIdentity before = app.Manager.Current;

        using HttpResponseMessage refused = await app.PostJson(Prefix + "/renew");
        Assert.AreEqual(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.AreSame(before, app.Manager.Current);

        allow = true;
        using HttpResponseMessage accepted = await app.PostJson(Prefix + "/renew");
        Assert.AreEqual(HttpStatusCode.OK, accepted.StatusCode);
        Assert.AreNotSame(before, app.Manager.Current);
    }

    [TestMethod]
    public async Task ReadEndpoints_AreOpenToTheLan()
    {
        await using TestApp app = await TestApp.Start();

        foreach (string path in new[] { "/ca.crt", "/ca.pem", "/ca.mobileconfig", "/info.json", "/" })
        {
            using HttpResponseMessage response = await app.Get(Prefix + path, SetLanClient);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, path);
        }

        static void SetLanClient(HttpRequestMessage request)
        {
            request.Headers.Add(TestApp.RemoteHeader, "192.168.1.50");
            request.Headers.Host = "192.168.1.10:9090";
        }
    }

    [TestMethod]
    public async Task NoResponse_ContainsPrivateKeyMaterial()
    {
        await using TestApp app = await TestApp.Start();
        List<byte[]> bodies = [];
        List<StoredIdentity> stored = [];
        try
        {
            stored.Add(app.LoadStored());
            await Collect();

            // After a renew the leaf key is new; after a reset both keys are. The old and the new keys must be absent.
            using (HttpResponseMessage renew = await app.PostJson(Prefix + "/renew"))
            {
                bodies.Add(await renew.Content.ReadAsByteArrayAsync());
            }

            stored.Add(app.LoadStored());
            await Collect();
            using (HttpResponseMessage reset = await app.PostJson(Prefix + "/reset"))
            {
                bodies.Add(await reset.Content.ReadAsByteArrayAsync());
            }

            stored.Add(app.LoadStored());
            await Collect();

            // Failure responses too.
            foreach (string path in new[] { "/renew", "/reset" })
            {
                using HttpResponseMessage refused = await app.PostJson(Prefix + path, request => request.Headers.Add(TestApp.RemoteHeader, "192.168.1.50"));
                bodies.Add(await refused.Content.ReadAsByteArrayAsync());
                using HttpResponseMessage wrongType = await app.PostJson(Prefix + path, request => request.Content = Body("text/plain"));
                bodies.Add(await wrongType.Content.ReadAsByteArrayAsync());
            }

            Assert.IsGreaterThan(10, bodies.Count);
            foreach (StoredIdentity identity in stored)
            {
                foreach (byte[] body in bodies)
                {
                    AssertNoKeys(identity, body);
                }
            }
        }
        finally
        {
            foreach (StoredIdentity identity in stored)
            {
                identity.Dispose();
            }
        }

        async Task Collect()
        {
            foreach (string path in new[] { "/", "/ca.crt", "/ca.pem", "/ca.mobileconfig", "/info.json" })
            {
                bodies.Add(await app.Client.GetByteArrayAsync(Prefix + path));
            }
        }
    }

    /// <summary>Neither the PKCS#8 keys nor their private scalars appear in <paramref name="body"/>, as bytes, text, base64, hex or PEM.</summary>
    internal static void AssertNoKeys(StoredIdentity identity, byte[] body)
    {
        string text = Encoding.Latin1.GetString(body);
        KeyMaterial.AssertAbsent(identity, text);
        foreach (byte[] pkcs8 in new[] { identity.CaPrivateKeyPkcs8, identity.LeafPrivateKeyPkcs8 })
        {
            using ECDsa key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(pkcs8, out _);
            byte[] scalar = key.ExportParameters(includePrivateParameters: true).D!;
            Assert.AreEqual(-1, body.AsSpan().IndexOf(pkcs8), "PKCS#8 bytes in a response.");
            Assert.AreEqual(-1, body.AsSpan().IndexOf(scalar), "A private scalar in a response.");
        }

        Assert.DoesNotContain("PRIVATE KEY", text, StringComparison.Ordinal);
    }

    private static StringContent Body(string contentType)
    {
        StringContent content = new("{}");
        content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType);
        return content;
    }

    private sealed class DelegateGate(string kind, Func<HttpContext, bool> allow) : ITlsCaGate
    {
        public string Kind => kind;

        public ValueTask<bool> IsAllowed(HttpContext context, TlsIdentity identity) => ValueTask.FromResult(allow(context));
    }
}
