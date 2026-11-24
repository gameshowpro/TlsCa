namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// A TLS server on a loopback TCP port. It accepts connections until disposed, and asks for the server options on
/// every handshake, the way Kestrel calls its <c>ServerCertificateSelector</c> per connection.
/// </summary>
internal sealed class LoopbackTlsServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Func<SslServerAuthenticationOptions> _options;
    private readonly Lock _lock = new();
    private readonly List<Task> _connections = [];
    private readonly List<Exception> _failures = [];
    private readonly Task _acceptLoop;
    private int _accepted;

    private LoopbackTlsServer(Func<SslServerAuthenticationOptions> options)
    {
        _options = options;
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptLoop = AcceptLoop();
    }

    public int Port { get; }

    public int Accepted => Volatile.Read(ref _accepted);

    public IReadOnlyList<Exception> Failures
    {
        get
        {
            lock (_lock)
            {
                return [.. _failures];
            }
        }
    }

    /// <summary>Serves whatever <paramref name="selectCertificate"/> returns at each handshake, as Kestrel's selector does.</summary>
    public static LoopbackTlsServer WithSelector(Func<X509Certificate2> selectCertificate) =>
        new(() => new()
        {
            ServerCertificateSelectionCallback = (_, _) => selectCertificate(),
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ClientCertificateRequired = false,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        });

    public static LoopbackTlsServer WithOptions(Func<SslServerAuthenticationOptions> options) => new(options);

    /// <summary>
    /// Connects as a client that trusts only <paramref name="trustedCa"/> (custom root trust) and validates
    /// <paramref name="targetHost"/>. Reports what the server sent and whether the handshake succeeded.
    /// </summary>
    public async Task<HandshakeResult> Connect(string targetHost, X509Certificate2 trustedCa, SslProtocols protocol)
    {
        using TcpClient tcp = new();
        await tcp.ConnectAsync(IPAddress.Loopback, Port);
        await using SslStream ssl = new(tcp.GetStream(), leaveInnerStreamOpen: false);
        X509ChainPolicy policy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        };
        _ = policy.CustomTrustStore.Add(trustedCa);
        SslPolicyErrors errors = SslPolicyErrors.None;
        byte[]? leaf = null;
        byte[][] alsoSent = [];
        SslClientAuthenticationOptions options = new()
        {
            TargetHost = targetHost,
            EnabledSslProtocols = protocol,
            CertificateChainPolicy = policy,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = Validate,
        };

        try
        {
            await ssl.AuthenticateAsClientAsync(options);
            byte[] buffer = new byte[1];
            int read = await ssl.ReadAsync(buffer);
            return new(read == 1 && buffer[0] == 42, errors, leaf, alsoSent, ssl.SslProtocol);
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException)
        {
            // IOException: the server dropped the connection during the handshake.
            return new(false, errors, leaf, alsoSent, SslProtocols.None);
        }

        bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            errors = sslPolicyErrors;
            leaf = certificate?.GetRawCertData();
            // SslStream adds every additional certificate the peer sent to the chain policy's extra store.
            alsoSent = [.. (chain?.ChainPolicy.ExtraStore ?? []).Select(c => c.RawData).Where(der => leaf is null || !der.AsSpan().SequenceEqual(leaf))];
            return sslPolicyErrors == SslPolicyErrors.None;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listener.Stop();
        await _acceptLoop;
        Task[] connections;
        lock (_lock)
        {
            connections = [.. _connections];
        }

        await Task.WhenAll(connections);
        _stop.Dispose();
    }

    private async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                return;
            }

            _ = Interlocked.Increment(ref _accepted);
            lock (_lock)
            {
                _connections.Add(Serve(client));
            }
        }
    }

    private async Task Serve(TcpClient client)
    {
        try
        {
            using (client)
            {
                await using SslStream ssl = new(client.GetStream(), leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(_options(), _stop.Token);
                await ssl.WriteAsync("*"u8.ToArray(), _stop.Token);
                await ssl.FlushAsync(_stop.Token);
                // Wait for the client to finish reading and close.
                _ = await ssl.ReadAsync(new byte[1], _stop.Token);
            }
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException or OperationCanceledException or SocketException)
        {
            lock (_lock)
            {
                _failures.Add(exception);
            }
        }
    }
}

/// <summary>The outcome of one client handshake.</summary>
/// <param name="Connected">The handshake succeeded and application data arrived.</param>
/// <param name="Errors">The client's validation result.</param>
/// <param name="Leaf">The server's end-entity certificate, as received.</param>
/// <param name="AlsoSent">Every other certificate the server sent.</param>
/// <param name="Protocol">The negotiated protocol.</param>
internal sealed record HandshakeResult(bool Connected, SslPolicyErrors Errors, byte[]? Leaf, byte[][] AlsoSent, SslProtocols Protocol);
