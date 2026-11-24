namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// An ASP.NET Core app with the TLS CA on <c>TestServer</c> (no sockets, no mDNS). <c>TestServer</c> has no remote
/// address, so a small middleware, in the test only, sets <c>Connection.RemoteIpAddress</c> from the
/// <see cref="RemoteHeader"/> request header (loopback when absent, none for <c>none</c>). The library's production
/// check is unchanged: it reads only <c>Connection.RemoteIpAddress</c>.
/// </summary>
internal sealed class TestApp : IAsyncDisposable
{
    public const string RemoteHeader = "X-Test-Remote";

    private readonly TempDirectory _directory;

    private TestApp(WebApplication app, TempDirectory directory)
    {
        App = app;
        _directory = directory;
        Client = app.GetTestClient();
    }

    public WebApplication App { get; }

    public HttpClient Client { get; }

    public string StorageDirectory => _directory.Path;

    public TlsIdentityManager Manager => App.Services.GetRequiredService<TlsIdentityManager>();

    public ITlsCaStatus Status => App.Services.GetRequiredService<ITlsCaStatus>();

    /// <summary>Builds and starts the app on <c>TestServer</c>, with the CA's endpoints mapped.</summary>
    /// <param name="configure">Changes the options after the test defaults.</param>
    /// <param name="logs">Receives the app's log entries; none are kept when null.</param>
    /// <param name="prepareStorage">Runs on the storage directory (which does not exist yet) before the app is built.</param>
    public static async Task<TestApp> Start(Action<TlsCaOptions>? configure = null, ILoggerProvider? logs = null, Action<string>? prepareStorage = null)
    {
        TempDirectory directory = new();
        prepareStorage?.Invoke(directory.Path);
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        _ = builder.Logging.ClearProviders();
        if (logs is not null)
        {
            _ = builder.Logging.AddProvider(logs);
            _ = builder.Logging.SetMinimumLevel(LogLevel.Information);
        }

        _ = builder.WebHost.UseTestServer();
        _ = builder.AddGameshowProTlsCa(ConfigureOptions);
        WebApplication app = builder.Build();
        _ = app.Use(SetRemoteAddress);
        _ = app.MapGameshowProTlsCa();
        await app.StartAsync();
        return new(app, directory);

        void ConfigureOptions(TlsCaOptions options)
        {
            options.Product = "TriggerGate";
            options.AppLabel = "triggergate";
            options.StorageDirectory = directory.Path;
            options.HttpPort = 9090;
            options.HttpsPort = 9443;
            options.Version = "2.1.7";
            options.AdvertiseMdns = false;
            configure?.Invoke(options);
        }
    }

    public Task<HttpResponseMessage> Get(string path, Action<HttpRequestMessage>? configure = null) => Send(HttpMethod.Get, path, configure);

    /// <summary>Posts a JSON body carrying a time, as the page does.</summary>
    public Task<HttpResponseMessage> PostJson(string path, Action<HttpRequestMessage>? configure = null)
    {
        return Send(HttpMethod.Post, path, ConfigureJson);

        void ConfigureJson(HttpRequestMessage request)
        {
            request.Content = new StringContent("{\"time\":1795300000}", Encoding.UTF8, "application/json");
            configure?.Invoke(request);
        }
    }

    public async Task<HttpResponseMessage> Send(HttpMethod method, string path, Action<HttpRequestMessage>? configure = null)
    {
        using HttpRequestMessage request = new(method, path);
        configure?.Invoke(request);
        return await Client.SendAsync(request);
    }

    /// <summary>The stored identity, read from disk. The caller disposes it.</summary>
    public StoredIdentity LoadStored()
    {
        FileIdentityStore store = new(StorageDirectory, FileIdentityStore.DefaultKeyProtector());
        return store.Load() ?? throw new InvalidOperationException("No identity is stored.");
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await App.StopAsync();
        await App.DisposeAsync();
        _directory.Dispose();
    }

    private static Task SetRemoteAddress(HttpContext context, Func<Task> next)
    {
        string? remote = context.Request.Headers[RemoteHeader];
        if (remote is null)
        {
            context.Connection.RemoteIpAddress = IPAddress.Loopback;
        }
        else if (remote != "none")
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse(remote);
        }

        return next();
    }
}
