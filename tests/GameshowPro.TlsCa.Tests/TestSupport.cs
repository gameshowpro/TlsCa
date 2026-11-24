namespace GameshowPro.TlsCa.Tests;

/// <summary>Allocates distinct ports for real-listener tests while checking both IPv4 and IPv6 binding space.</summary>
internal static class TestPorts
{
    private static readonly Lock s_gate = new();
    private static readonly HashSet<int> s_used = [];

    public static int Reserve()
    {
        lock (s_gate)
        {
            for (int attempt = 0; attempt < 1_000; attempt++)
            {
                TcpListener listener = new(Socket.OSSupportsIPv6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
                listener.Server.ExclusiveAddressUse = true;
                if (Socket.OSSupportsIPv6)
                {
                    listener.Server.DualMode = true;
                }

                try
                {
                    listener.Start();
                    int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                    if (s_used.Add(port))
                    {
                        return port;
                    }
                }
                finally
                {
                    listener.Stop();
                }
            }
        }

        throw new InvalidOperationException("Could not reserve a unique test port.");
    }
}

/// <summary>A unique directory under the system temporary directory (outside the repository), deleted on dispose.</summary>
internal sealed class TempDirectory : IDisposable
{
    public static readonly string Root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "GameshowPro.TlsCa.Tests");

    public TempDirectory()
    {
        // Not created: the store must create (and protect) its directory itself.
        Path = System.IO.Path.Combine(Root, Guid.NewGuid().ToString("N"));
    }

    public string Path { get; }

    public string IdentityFile => System.IO.Path.Combine(Path, FileIdentityStore.FileName);

    public FileIdentityStore CreateStore() => new(Path, FileIdentityStore.DefaultKeyProtector());

    public void Dispose()
    {
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}

[TestClass]
public sealed class TestAssembly
{
    [AssemblyInitialize]
    public static void RecordCertificateStores(TestContext _) => CertificateStoreGuard.Record();

    /// <summary>
    /// Removes the shared temporary root once every test has removed its own directory, and fails the run if a test left
    /// a certificate in one of the user's certificate stores.
    /// </summary>
    [AssemblyCleanup]
    public static void CleanUp()
    {
        if (Directory.Exists(TempDirectory.Root) && !Directory.EnumerateFileSystemEntries(TempDirectory.Root).Any())
        {
            Directory.Delete(TempDirectory.Root);
        }

        IReadOnlyList<string> left = CertificateStoreGuard.RemoveAdded();
        Assert.IsEmpty(left, $"Tests added certificates to the user's certificate stores: {string.Join("; ", left)}");
    }
}

/// <summary>
/// Guards the rule that a test run adds nothing to a Windows certificate store. On Windows, SChannel adds the
/// intermediates of a server certificate context to the user's Intermediate Certification Authorities store, so a test
/// that serves a chain leaves a certificate behind on every run. The stores are recorded before the first test; after
/// the last, any certificate that was added and does not chain to a root the machine trusts (no test certificate does)
/// is removed and reported, which fails the run.
/// </summary>
internal static class CertificateStoreGuard
{
    private static readonly StoreName[] s_stores = [StoreName.CertificateAuthority, StoreName.My, StoreName.Root];
    private static readonly Dictionary<StoreName, HashSet<string>> s_before = [];

    public static void Record()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        foreach (StoreName name in s_stores)
        {
            using X509Store store = new(name, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            s_before[name] = [.. store.Certificates.Select(certificate => certificate.Thumbprint)];
        }
    }

    /// <summary>Removes what the run added and returns a description of each certificate found.</summary>
    public static IReadOnlyList<string> RemoveAdded()
    {
        List<string> found = [];
        foreach ((StoreName name, HashSet<string> before) in s_before)
        {
            using X509Store store = new(name, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            foreach (X509Certificate2 certificate in store.Certificates)
            {
                if (before.Contains(certificate.Thumbprint) || ChainsToATrustedRoot(certificate))
                {
                    continue;
                }

                string description = $"{name}: {certificate.Subject} ({certificate.Thumbprint})";

                // Removing from the root store shows a confirmation dialog, so that one is only reported.
                if (name == StoreName.Root)
                {
                    found.Add(description + ", not removed");
                }
                else
                {
                    store.Remove(certificate);
                    found.Add(description + ", removed");
                }
            }
        }

        return found;
    }

    // Windows itself caches public intermediates in the user's store; those chain to a trusted root and are left alone.
    private static bool ChainsToATrustedRoot(X509Certificate2 certificate)
    {
        using X509Chain chain = new();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        return chain.Build(certificate);
    }
}

/// <summary>A clock that only moves when told to. Timers are real timers.</summary>
internal sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
{
    private long _utcTicks = now.UtcTicks;

    public DateTimeOffset Now
    {
        get => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);
        set => Interlocked.Exchange(ref _utcTicks, value.UtcTicks);
    }

    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>Records every log entry as text, including exception details, so tests can search it for key material.</summary>
internal sealed class CollectingLogger : ILogger
{
    private readonly Lock _lock = new();
    private readonly List<string> _entries = [];

    public IReadOnlyList<string> Entries
    {
        get
        {
            lock (_lock)
            {
                return [.. _entries];
            }
        }
    }

    public string AllText => string.Join(Environment.NewLine, Entries);

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        string entry = $"{logLevel}: {formatter(state, exception)}{(exception is null ? "" : Environment.NewLine + exception)}";
        lock (_lock)
        {
            _entries.Add(entry);
        }
    }
}

/// <summary>A logger provider for a whole app: every entry as <c>Level: message</c>, from every category.</summary>
internal sealed class TestLogProvider : ILoggerProvider, ILogger
{
    private readonly Lock _lock = new();
    private readonly List<string> _messages = [];

    public IReadOnlyList<string> Messages
    {
        get
        {
            lock (_lock)
            {
                return [.. _messages];
            }
        }
    }

    /// <summary>The entries at <paramref name="level"/> or above.</summary>
    public IReadOnlyList<string> AtLeast(LogLevel level) =>
        [.. Messages.Where(message => Enum.TryParse(message[..message.IndexOf(':', StringComparison.Ordinal)], out LogLevel entry) && entry >= level)];

    public ILogger CreateLogger(string categoryName) => this;

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        lock (_lock)
        {
            _messages.Add($"{logLevel}: {formatter(state, exception)}");
        }
    }

    public void Dispose()
    {
    }
}

/// <summary>Ways to leave a storage directory in a state from which no identity can be loaded or created.</summary>
internal static class BrokenStorage
{
    /// <summary>An <c>identity.json</c> that is not JSON. Returns its bytes, which nothing may change.</summary>
    public static byte[] WriteCorruptIdentity(string storageDirectory)
    {
        _ = Directory.CreateDirectory(storageDirectory);
        byte[] corrupt = Encoding.UTF8.GetBytes("{ \"formatVersion\": 1, \"name\": ");
        File.WriteAllBytes(Path.Combine(storageDirectory, FileIdentityStore.FileName), corrupt);
        return corrupt;
    }

    /// <summary>
    /// A storage directory below a file, so nothing can be read (there is no identity) and nothing can be written. Returns
    /// the storage directory to configure.
    /// </summary>
    public static string Unwritable(string directory)
    {
        _ = Directory.CreateDirectory(directory);
        string blocker = Path.Combine(directory, "blocker");
        File.WriteAllText(blocker, "not a directory");
        return Path.Combine(blocker, "tls");
    }
}

internal static class TestManagers
{
    public const string AppLabel = "triggergate";
    public const string HostName = "Studio PC";
    public const string Name = "studio-pc-triggergate";

    /// <summary>The minimum time used by lifecycle tests, so they do not depend on when the library was built.</summary>
    public static readonly DateTimeOffset MinimumTime = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static TlsCaOptions Options(Action<TlsCaOptions>? configure = null)
    {
        TlsCaOptions options = new()
        {
            Product = "TriggerGate",
            AppLabel = AppLabel,
            MinimumTime = MinimumTime,
        };
        configure?.Invoke(options);
        return options;
    }

    public static TlsIdentityManager Create(
        IIdentityStore store,
        TimeProvider time,
        Func<string>? hostName = null,
        Action<TlsCaOptions>? configure = null,
        ILogger? logger = null,
        TimeSpan? retiredCertificateGrace = null)
    {
        TlsCaOptions options = Options(configure);
        Func<string> host = hostName ?? (() => HostName);
        return retiredCertificateGrace is { } grace
            ? new(options, store, time, logger, host) { RetiredCertificateGrace = grace }
            : new(options, store, time, logger, host);
    }
}

internal static class KeyMaterial
{
    /// <summary>Every textual form of the private keys in <paramref name="identity"/> that could leak into text.</summary>
    public static IEnumerable<string> Forms(StoredIdentity identity)
    {
        foreach (byte[] pkcs8 in new[] { identity.CaPrivateKeyPkcs8, identity.LeafPrivateKeyPkcs8 })
        {
            using ECDsa key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(pkcs8, out _);
            byte[] scalar = key.ExportParameters(includePrivateParameters: true).D!;
            yield return Convert.ToBase64String(pkcs8);
            yield return Convert.ToHexString(pkcs8);
            yield return Convert.ToHexString(scalar);
            yield return Convert.ToBase64String(scalar);
            yield return key.ExportPkcs8PrivateKeyPem();
        }
    }

    public static void AssertAbsent(StoredIdentity identity, string text)
    {
        foreach (string form in Forms(identity))
        {
            Assert.DoesNotContain(form, text, StringComparison.OrdinalIgnoreCase, "Key material appeared in text.");
        }
    }
}
