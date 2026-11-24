namespace GameshowPro.TlsCa;

/// <summary>
/// Stores the identity as one JSON file, <see cref="FileName"/>, in a directory whose permissions are restricted before
/// the first key is written: on Windows an ACL with inheritance removed that grants full control to SYSTEM,
/// Administrators and the current account only; elsewhere directory mode 0700 and file mode 0600. Private keys pass
/// through an <see cref="IKeyProtector"/> before they touch disk. Every write goes to a temporary file in the same
/// directory, is flushed to disk, then replaces the identity file in one rename.
/// </summary>
public sealed partial class FileIdentityStore : IIdentityStore
{
    /// <summary>The identity file's name inside the storage directory.</summary>
    public const string FileName = "identity.json";

    private const string TemporarySuffix = ".tmp";
    private const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode FilePermissions = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly IKeyProtector _keyProtector;
    private readonly ILogger _logger;

    /// <summary>Creates a store for the identity file in <paramref name="directory"/>.</summary>
    /// <param name="directory">The storage directory. It is created on the first save.</param>
    /// <param name="keyProtector">Protects the private keys at rest; see <see cref="DefaultKeyProtector"/>.</param>
    /// <param name="logger">Receives diagnostics, which never include key material.</param>
    public FileIdentityStore(string directory, IKeyProtector keyProtector, ILogger<FileIdentityStore>? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(keyProtector);
        StorageDirectory = Path.GetFullPath(directory);
        FilePath = Path.Combine(StorageDirectory, FileName);
        _keyProtector = keyProtector;
        _logger = logger ?? NullLogger<FileIdentityStore>.Instance;
    }

    /// <summary>The storage directory (full path).</summary>
    public string StorageDirectory { get; }

    /// <summary>The identity file (full path).</summary>
    public string FilePath { get; }

    /// <summary>Test hook: runs after the temporary file is flushed and before it replaces the identity file.</summary>
    internal Action<string>? BeforeReplace { get; set; }

    /// <summary>The protector for this platform: DPAPI (machine scope) on Windows, none elsewhere.</summary>
    public static IKeyProtector DefaultKeyProtector() =>
        OperatingSystem.IsWindows() ? new DpapiKeyProtector() : new PassthroughKeyProtector();

    /// <inheritdoc/>
    public StoredIdentity? Load()
    {
        byte[] json;
        try
        {
            json = File.ReadAllBytes(FilePath);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IdentityStoreException(
                $"The TLS identity file '{FilePath}' exists but cannot be read ({exception.GetType().Name}). Check the permissions "
                + "of the file and its directory for the account running this app. " + Recovery, exception);
        }

        try
        {
            IdentityFile file = Parse(json);
            if (file.FormatVersion != IdentityFile.CurrentFormatVersion)
            {
                throw Corrupt($"its format version {file.FormatVersion} is not supported (expected {IdentityFile.CurrentFormatVersion})");
            }

            if (file.KeyProtection != _keyProtector.Id)
            {
                throw new IdentityStoreException(
                    $"The TLS identity file '{FilePath}' holds keys protected with '{file.KeyProtection}', but this app unprotects "
                    + $"keys with '{_keyProtector.Id}'. " + Recovery);
            }

            byte[] caKey = Unprotect(file.CaPrivateKey);
            byte[] leafKey;
            try
            {
                leafKey = Unprotect(file.LeafPrivateKey);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(caKey);
                throw;
            }

            LogLoaded(FilePath);
            return new()
            {
                Name = file.Name,
                CaCertificateDer = file.CaCertificate,
                CaPrivateKeyPkcs8 = caKey,
                LeafCertificateDer = file.LeafCertificate,
                LeafPrivateKeyPkcs8 = leafKey,
                PreviousCaFingerprintSha256 = file.PreviousCaFingerprintSha256,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
        }

        IdentityFile Parse(byte[] json)
        {
            try
            {
                return JsonSerializer.Deserialize(json, IdentityFileJsonContext.Default.IdentityFile)
                    ?? throw Corrupt("it holds no identity");
            }
            catch (JsonException exception)
            {
                // The JSON exception is not chained: its message may quote the offending input. Path and position only.
                throw Corrupt($"it is not a valid identity file (at {exception.Path ?? "$"}, line {exception.LineNumber + 1})");
            }
        }

        byte[] Unprotect(byte[] protectedKey)
        {
            try
            {
                return _keyProtector.Unprotect(protectedKey);
            }
#pragma warning disable CA1031 // Whatever the protector throws, the identity cannot be used; the cause is kept as the inner exception.
            catch (Exception exception) when (exception is not (OperationCanceledException or ObjectDisposedException))
#pragma warning restore CA1031
            {
                throw new IdentityStoreException(
                    $"The private keys in the TLS identity file '{FilePath}' cannot be decrypted with '{_keyProtector.Id}' "
                    + $"({exception.GetType().Name}). The file may come from another machine or be damaged, or the key "
                    + "protection may be unavailable to the account running this app. " + Recovery, exception);
            }
        }
    }

    /// <inheritdoc/>
    public void Save(StoredIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        DeviceName.ThrowIfInvalid(identity.Name, nameof(identity));
        byte[] caKey = Protect(identity.CaPrivateKeyPkcs8);
        byte[] leafKey;
        try
        {
            leafKey = Protect(identity.LeafPrivateKeyPkcs8);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(caKey);
            throw;
        }

        IdentityFile file = new()
        {
            FormatVersion = IdentityFile.CurrentFormatVersion,
            Name = identity.Name,
            KeyProtection = _keyProtector.Id,
            CaCertificate = identity.CaCertificateDer,
            CaPrivateKey = caKey,
            LeafCertificate = identity.LeafCertificateDer,
            LeafPrivateKey = leafKey,
            PreviousCaFingerprintSha256 = identity.PreviousCaFingerprintSha256,
        };
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(file, IdentityFileJsonContext.Default.IdentityFile);
        string temporaryPath = Path.Combine(StorageDirectory, $"{FileName}.{Guid.NewGuid():N}{TemporarySuffix}");
        bool replaced = false;
        try
        {
            // Protections first: no key byte is written before the directory is restricted.
            EnsureProtectedDirectory();
            DeleteStaleTemporaryFiles();
            WriteFlushed(temporaryPath, json);
            BeforeReplace?.Invoke(temporaryPath);
            File.Move(temporaryPath, FilePath, overwrite: true);
            replaced = true;
            LogSaved(FilePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IdentityStoreException(
                $"The TLS identity could not be written to '{FilePath}' ({exception.GetType().Name}). Check the permissions of the "
                + "directory for the account running this app. The previous identity, if any, is unchanged.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(json);
            CryptographicOperations.ZeroMemory(caKey);
            CryptographicOperations.ZeroMemory(leafKey);
            if (!replaced)
            {
                TryDelete(temporaryPath);
            }
        }

        // Protects one private key for writing; any failure becomes an IdentityStoreException.
        byte[] Protect(byte[] privateKey)
        {
            try
            {
                return _keyProtector.Protect(privateKey);
            }
#pragma warning disable CA1031 // Whatever the protector throws, nothing can be saved; the cause is kept as the inner exception.
            catch (Exception exception) when (exception is not (OperationCanceledException or ObjectDisposedException))
#pragma warning restore CA1031
            {
                throw new IdentityStoreException(
                    $"The private keys of the TLS identity could not be protected with '{_keyProtector.Id}' for '{FilePath}' "
                    + $"({exception.GetType().Name}), so nothing was written. The key protection may be unavailable to the account "
                    + "running this app. The previous identity, if any, is unchanged.", exception);
            }
        }

        void EnsureProtectedDirectory()
        {
            string? parent = Path.GetDirectoryName(StorageDirectory);
            if (parent is not null)
            {
                _ = Directory.CreateDirectory(parent);
            }

            if (OperatingSystem.IsWindows())
            {
                DirectorySecurity security = CreateWindowsDirectorySecurity();
                DirectoryInfo directory = new(StorageDirectory);
                if (!directory.Exists)
                {
                    directory.Create(security);
                }

                // Applied every time, so an existing directory (for example one created by an installer) is restricted too.
                directory.SetAccessControl(security);
            }
            else
            {
                _ = Directory.CreateDirectory(StorageDirectory, DirectoryMode);
                File.SetUnixFileMode(StorageDirectory, DirectoryMode);
            }
        }

        void DeleteStaleTemporaryFiles()
        {
            foreach (string path in Directory.EnumerateFiles(StorageDirectory, FileName + ".*" + TemporarySuffix))
            {
                TryDelete(path);
            }
        }

        static void WriteFlushed(string path, byte[] contents)
        {
            FileStreamOptions options = new()
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = FilePermissions;
            }

            using (FileStream stream = new(path, options))
            {
                stream.Write(contents);
                stream.Flush(flushToDisk: true);
            }

            if (!OperatingSystem.IsWindows())
            {
                // The creation mode is subject to the umask, which can only remove bits; set it exactly.
                File.SetUnixFileMode(path, FilePermissions);
            }
        }
    }

    private const string Recovery =
        "A new identity is not created automatically, because that would break every client's trust in this device. "
        + "Restore access to the file, or reset the identity explicitly (clients must then install the new CA certificate).";

    private IdentityStoreException Corrupt(string reason) =>
        new($"The TLS identity file '{FilePath}' is corrupt: {reason}. " + Recovery);

    /// <summary>
    /// A protected DACL (no inherited entries) granting full control, inherited by files and subdirectories, to SYSTEM,
    /// Administrators and the current account.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static DirectorySecurity CreateWindowsDirectorySecurity()
    {
        DirectorySecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        foreach (SecurityIdentifier sid in AllowedWindowsAccounts(current))
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        return security;
    }

    /// <summary>SYSTEM, Administrators and the current account, without duplicates.</summary>
    [SupportedOSPlatform("windows")]
    internal static ImmutableArray<SecurityIdentifier> AllowedWindowsAccounts(WindowsIdentity current) =>
    [
        .. new[]
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            current.User ?? throw new InvalidOperationException("The current Windows account has no security identifier."),
        }.Distinct(),
    ];

    private void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            LogTemporaryFileNotDeleted(path, exception.GetType().Name);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Loaded the TLS identity from {Path}")]
    private partial void LogLoaded(string path);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Saved the TLS identity to {Path}")]
    private partial void LogSaved(string path);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not delete the temporary identity file {Path} ({Error})")]
    private partial void LogTemporaryFileNotDeleted(string path, string error);
}

/// <summary>The on-disk form of a <see cref="StoredIdentity"/>. Byte arrays are base64 in the JSON.</summary>
internal sealed class IdentityFile
{
    public const int CurrentFormatVersion = 1;

    public required int FormatVersion { get; init; }

    public required string Name { get; init; }

    /// <summary>The <see cref="IKeyProtector.Id"/> that protected the two private keys.</summary>
    public required string KeyProtection { get; init; }

    public required byte[] CaCertificate { get; init; }

    public required byte[] CaPrivateKey { get; init; }

    public required byte[] LeafCertificate { get; init; }

    public required byte[] LeafPrivateKey { get; init; }

    public string? PreviousCaFingerprintSha256 { get; init; }
}

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true)]
[JsonSerializable(typeof(IdentityFile))]
internal sealed partial class IdentityFileJsonContext : JsonSerializerContext;
