namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Acceptance test 7: atomic replace; key bytes on disk are not plain PKCS#8 on Windows; permissions (Windows ACL,
/// Linux modes); a corrupt or unreadable file is an error, not a silent reset.
/// </summary>
[TestClass]
public sealed class StoreTests
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 22, 10, 30, 15, TimeSpan.Zero);

    [TestMethod]
    public void Load_NoDirectoryOrNoFile_ReturnsNull()
    {
        using TempDirectory directory = new();
        Assert.IsNull(directory.CreateStore().Load());
        _ = Directory.CreateDirectory(directory.Path);
        Assert.IsNull(directory.CreateStore().Load());
    }

    [TestMethod]
    public void SaveThenLoad_RoundTripsEveryField()
    {
        using TempDirectory directory = new();
        using StoredIdentity original = NewIdentity("fingerprint-of-an-older-ca");

        directory.CreateStore().Save(original);
        using StoredIdentity? loaded = directory.CreateStore().Load();

        Assert.IsNotNull(loaded);
        Assert.AreEqual(original.Name, loaded.Name);
        CollectionAssert.AreEqual(original.CaCertificateDer, loaded.CaCertificateDer);
        CollectionAssert.AreEqual(original.CaPrivateKeyPkcs8, loaded.CaPrivateKeyPkcs8);
        CollectionAssert.AreEqual(original.LeafCertificateDer, loaded.LeafCertificateDer);
        CollectionAssert.AreEqual(original.LeafPrivateKeyPkcs8, loaded.LeafPrivateKeyPkcs8);
        Assert.AreEqual(original.PreviousCaFingerprintSha256, loaded.PreviousCaFingerprintSha256);
        CollectionAssert.AreEqual(new[] { FileIdentityStore.FileName }, Directory.GetFiles(directory.Path).Select(Path.GetFileName).ToArray(), "One file, no leftovers.");
    }

    [TestMethod]
    public void Save_WritesATemporaryFileThenReplacesTheIdentityInOneStep()
    {
        using TempDirectory directory = new();
        using StoredIdentity first = NewIdentity();
        using StoredIdentity second = NewIdentity();
        FileIdentityStore store = directory.CreateStore();
        store.Save(first);
        bool hookRan = false;
        store.BeforeReplace = CheckTemporaryIdentity;

        void CheckTemporaryIdentity(string temporaryPath)
        {
            hookRan = true;
            // The new identity is complete on disk, beside the old one, which is still the identity in force.
            Assert.AreEqual(directory.Path, Path.GetDirectoryName(temporaryPath));
            Assert.AreNotEqual(directory.IdentityFile, temporaryPath);
            Assert.IsTrue(File.Exists(temporaryPath));
            using StoredIdentity? stillFirst = directory.CreateStore().Load();
            CollectionAssert.AreEqual(first.CaCertificateDer, stillFirst!.CaCertificateDer);
        }

        store.Save(second);

        Assert.IsTrue(hookRan);
        using StoredIdentity? loaded = directory.CreateStore().Load();
        CollectionAssert.AreEqual(second.CaCertificateDer, loaded!.CaCertificateDer);
        Assert.HasCount(1, Directory.GetFiles(directory.Path));
    }

    [TestMethod]
    public void Save_InterruptedBeforeTheReplace_LeavesThePreviousIdentityIntact()
    {
        using TempDirectory directory = new();
        using StoredIdentity first = NewIdentity();
        using StoredIdentity second = NewIdentity();
        FileIdentityStore store = directory.CreateStore();
        store.Save(first);
        byte[] before = File.ReadAllBytes(directory.IdentityFile);
        store.BeforeReplace = _ => throw new IOException("Simulated crash between the flush and the rename.");

        IdentityStoreException exception = Assert.ThrowsExactly<IdentityStoreException>(() => store.Save(second));

        StringAssert.Contains(exception.Message, "unchanged");
        CollectionAssert.AreEqual(before, File.ReadAllBytes(directory.IdentityFile));
        using StoredIdentity? loaded = directory.CreateStore().Load();
        CollectionAssert.AreEqual(first.CaCertificateDer, loaded!.CaCertificateDer);
        Assert.HasCount(1, Directory.GetFiles(directory.Path), "The temporary file was removed.");
    }

    [TestMethod]
    public void TemporaryFileLeftByACrash_IsIgnoredByLoadAndRemovedBySave()
    {
        using TempDirectory directory = new();
        using StoredIdentity first = NewIdentity();
        FileIdentityStore store = directory.CreateStore();
        store.Save(first);
        string leftover = Path.Combine(directory.Path, FileIdentityStore.FileName + ".0123456789abcdef.tmp");
        File.WriteAllText(leftover, "{\"half\":");

        using (StoredIdentity? loaded = store.Load())
        {
            CollectionAssert.AreEqual(first.CaCertificateDer, loaded!.CaCertificateDer);
        }

        using StoredIdentity second = NewIdentity();
        store.Save(second);
        Assert.IsFalse(File.Exists(leftover));
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public void KeysOnDisk_AreDpapiProtectedNotPlainPkcs8_OnWindows()
    {
        using TempDirectory directory = new();
        using StoredIdentity identity = NewIdentity();

        directory.CreateStore().Save(identity);

        string text = File.ReadAllText(directory.IdentityFile);
        KeyMaterial.AssertAbsent(identity, text);
        using JsonDocument document = JsonDocument.Parse(text);
        JsonElement root = document.RootElement;
        Assert.AreEqual(DpapiKeyProtector.SchemeId, root.GetProperty("keyProtection").GetString());
        foreach ((string property, byte[] plain) in new[] { ("caPrivateKey", identity.CaPrivateKeyPkcs8), ("leafPrivateKey", identity.LeafPrivateKeyPkcs8) })
        {
            byte[] onDisk = root.GetProperty(property).GetBytesFromBase64();
            Assert.IsFalse(onDisk.AsSpan().IndexOf(plain) >= 0, $"{property} holds the plain PKCS#8.");
            using ECDsa key = ECDsa.Create();
            _ = Assert.Throws<CryptographicException>(() => key.ImportPkcs8PrivateKey(onDisk, out _), $"{property} must not import as PKCS#8.");
        }

        // The certificates are public and stored as they are.
        CollectionAssert.AreEqual(identity.CaCertificateDer, root.GetProperty("caCertificate").GetBytesFromBase64());
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public void Directory_IsRestrictedToSystemAdministratorsAndTheCurrentAccount_BeforeAnyKeyIsWritten_OnWindows()
    {
        using TempDirectory directory = new();
        // An existing directory inherits the temporary directory's ACL; the store must replace it.
        _ = Directory.CreateDirectory(directory.Path);
        Assert.IsFalse(new DirectoryInfo(directory.Path).GetAccessControl().AreAccessRulesProtected);
        using StoredIdentity identity = NewIdentity();
        FileIdentityStore store = directory.CreateStore();
        bool checkedBeforeReplace = false;
        store.BeforeReplace = CheckPermissionsBeforeReplace;

        void CheckPermissionsBeforeReplace(string temporaryPath)
        {
            // The first key bytes are in the temporary file now; the directory was restricted before it was created.
            AssertRestrictedDirectory(directory.Path);
            AssertInheritsOnlyTheRestrictedRules(temporaryPath);
            checkedBeforeReplace = true;
        }

        store.Save(identity);

        Assert.IsTrue(checkedBeforeReplace);
        AssertRestrictedDirectory(directory.Path);
        AssertInheritsOnlyTheRestrictedRules(directory.IdentityFile);

        static void AssertRestrictedDirectory(string path)
        {
            DirectorySecurity security = new DirectoryInfo(path).GetAccessControl();
            Assert.IsTrue(security.AreAccessRulesProtected, "Inheritance from the parent is removed.");
            FileSystemAccessRule[] rules = [.. security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()];
            CollectionAssert.AreEquivalent(ExpectedAccounts(), rules.Select(rule => rule.IdentityReference.Value).ToArray());
            foreach (FileSystemAccessRule rule in rules)
            {
                Assert.IsFalse(rule.IsInherited);
                Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
                Assert.AreEqual(FileSystemRights.FullControl, rule.FileSystemRights);
                Assert.AreEqual(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, rule.InheritanceFlags);
            }
        }

        static void AssertInheritsOnlyTheRestrictedRules(string path)
        {
            FileSecurity security = new FileInfo(path).GetAccessControl();
            FileSystemAccessRule[] rules = [.. security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()];
            CollectionAssert.AreEquivalent(ExpectedAccounts(), rules.Select(rule => rule.IdentityReference.Value).ToArray());
            Assert.IsTrue(rules.All(rule => rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights == FileSystemRights.FullControl));
        }

        static string[] ExpectedAccounts()
        {
            using WindowsIdentity current = WindowsIdentity.GetCurrent();
            return [.. new[] { "S-1-5-18", "S-1-5-32-544", current.User!.Value }.Distinct()];
        }
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Linux)]
    [UnsupportedOSPlatform("windows")]
    public void Permissions_AreDirectory0700AndFile0600_OnLinux()
    {
        using TempDirectory directory = new();
        _ = Directory.CreateDirectory(directory.Path);
        File.SetUnixFileMode(directory.Path, (UnixFileMode)0b111_101_101); // 0755, as an installer might leave it
        using StoredIdentity identity = NewIdentity();
        FileIdentityStore store = directory.CreateStore();
        UnixFileMode? temporaryMode = null;
        UnixFileMode? directoryModeBeforeReplace = null;
        store.BeforeReplace = CapturePermissionsBeforeReplace;

        void CapturePermissionsBeforeReplace(string temporaryPath)
        {
            temporaryMode = File.GetUnixFileMode(temporaryPath);
            directoryModeBeforeReplace = File.GetUnixFileMode(directory.Path);
        }

        store.Save(identity);

        const UnixFileMode Directory0700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        const UnixFileMode File0600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        Assert.AreEqual(Directory0700, directoryModeBeforeReplace, "The directory was restricted before the first key was written.");
        Assert.AreEqual(File0600, temporaryMode);
        Assert.AreEqual(Directory0700, File.GetUnixFileMode(directory.Path));
        Assert.AreEqual(File0600, File.GetUnixFileMode(directory.IdentityFile));
        Assert.AreEqual(PassthroughKeyProtector.SchemeId, FileIdentityStore.DefaultKeyProtector().Id, "Linux stores keys under file permissions only.");
    }

    [TestMethod]
    [DataRow("", DisplayName = "Empty file")]
    [DataRow("{", DisplayName = "Truncated JSON")]
    [DataRow("null", DisplayName = "JSON null")]
    [DataRow("[]", DisplayName = "Wrong JSON shape")]
    [DataRow("not json at all", DisplayName = "Not JSON")]
    public void Load_CorruptFile_ThrowsAClearError(string contents)
    {
        using TempDirectory directory = new();
        using StoredIdentity identity = NewIdentity();
        directory.CreateStore().Save(identity);
        File.WriteAllText(directory.IdentityFile, contents);

        AssertLoadFails(directory, identity, "corrupt");
    }

    [TestMethod]
    [DataRow("caPrivateKey", DisplayName = "Missing CA key")]
    [DataRow("leafCertificate", DisplayName = "Missing leaf certificate")]
    [DataRow("name", DisplayName = "Missing name")]
    public void Load_MissingField_ThrowsAClearError(string property)
    {
        using TempDirectory directory = new();
        using StoredIdentity identity = NewIdentity();
        directory.CreateStore().Save(identity);
        EditFile(directory, root => root.Remove(property));

        AssertLoadFails(directory, identity, "corrupt");
    }

    [TestMethod]
    public void Load_InvalidBase64OrUnknownVersion_ThrowsAClearError()
    {
        using TempDirectory directory = new();
        using StoredIdentity identity = NewIdentity();
        directory.CreateStore().Save(identity);
        string original = File.ReadAllText(directory.IdentityFile);

        EditFile(directory, root => root["leafPrivateKey"] = "!!! not base64 !!!");
        AssertLoadFails(directory, identity, "corrupt");

        File.WriteAllText(directory.IdentityFile, original);
        EditFile(directory, root => root["formatVersion"] = 2);
        AssertLoadFails(directory, identity, "format version 2");
    }

    [TestMethod]
    public void Load_KeysThatCannotBeUnprotected_ThrowsAClearError()
    {
        using TempDirectory directory = new();
        using StoredIdentity identity = NewIdentity();
        directory.CreateStore().Save(identity);
        EditFile(directory, TamperCaKey);

        static void TamperCaKey(JsonObject root)
        {
            byte[] tampered = Convert.FromBase64String(root["caPrivateKey"]!.GetValue<string>());
            tampered[^1] ^= 0xFF;
            root["caPrivateKey"] = Convert.ToBase64String(tampered);
        }

        if (OperatingSystem.IsWindows())
        {
            // DPAPI detects the tampering.
            AssertLoadFails(directory, identity, "cannot be decrypted");
        }
        else
        {
            // Without encryption the damage surfaces when the key is used: the manager reports it as inconsistent.
            using StoredIdentity? loaded = directory.CreateStore().Load();
            Assert.IsNotNull(loaded);
        }
    }

    [TestMethod]
    public void Load_KeysProtectedWithAnotherScheme_ThrowsAClearError()
    {
        using TempDirectory directory = new();
        using StoredIdentity identity = NewIdentity();
        new FileIdentityStore(directory.Path, new OtherProtector()).Save(identity);

        AssertLoadFails(directory, identity, "protected with 'other'");
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public void Load_UnreadableFile_ThrowsAClearError_OnWindows()
    {
        using TempDirectory directory = new();
        using StoredIdentity identity = NewIdentity();
        directory.CreateStore().Save(identity);
        FileInfo file = new(directory.IdentityFile);
        FileSecurity original = file.GetAccessControl();
        FileSecurity denied = new();
        denied.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        file.SetAccessControl(denied); // No entries: nobody may read it (the owner can still change the ACL).
        try
        {
            AssertLoadFails(directory, identity, "cannot be read");
        }
        finally
        {
            file.SetAccessControl(original);
        }
    }

    [TestMethod]
    [OSCondition(OperatingSystems.Linux)]
    [UnsupportedOSPlatform("windows")]
    public void Load_UnreadableFile_ThrowsAClearError_OnLinux()
    {
        using TempDirectory directory = new();
        using StoredIdentity identity = NewIdentity();
        directory.CreateStore().Save(identity);
        File.SetUnixFileMode(directory.IdentityFile, UnixFileMode.None);
        try
        {
            if (Environment.UserName == "root")
            {
                Assert.Inconclusive("File modes do not restrict root.");
            }

            AssertLoadFails(directory, identity, "cannot be read");
        }
        finally
        {
            File.SetUnixFileMode(directory.IdentityFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private static StoredIdentity NewIdentity(string? previousCaFingerprint = null)
    {
        using DeviceIdentity device = TestPki.CreateIdentity(TestPki.Name, s_now);
        return new()
        {
            Name = TestPki.Name,
            CaCertificateDer = device.Ca.RawData,
            CaPrivateKeyPkcs8 = device.CaKey.ExportPkcs8PrivateKey(),
            LeafCertificateDer = device.Leaf.RawData,
            LeafPrivateKeyPkcs8 = device.LeafKey.ExportPkcs8PrivateKey(),
            PreviousCaFingerprintSha256 = previousCaFingerprint,
        };
    }

    private static void EditFile(TempDirectory directory, Action<JsonObject> edit)
    {
        JsonObject root = JsonNode.Parse(File.ReadAllText(directory.IdentityFile))!.AsObject();
        edit(root);
        File.WriteAllText(directory.IdentityFile, root.ToJsonString());
    }

    /// <summary>Loading fails with a clear <see cref="IdentityStoreException"/>, free of key material, and changes nothing.</summary>
    private static void AssertLoadFails(TempDirectory directory, StoredIdentity identity, string expectedReason)
    {
        byte[]? before = TryRead(directory.IdentityFile);

        IdentityStoreException exception = Assert.ThrowsExactly<IdentityStoreException>(() => directory.CreateStore().Load());

        StringAssert.Contains(exception.Message, expectedReason);
        StringAssert.Contains(exception.Message, directory.IdentityFile);
        StringAssert.Contains(exception.Message, "not created automatically");
        KeyMaterial.AssertAbsent(identity, exception.ToString());
        CollectionAssert.AreEqual(before, TryRead(directory.IdentityFile), "A failed load changes nothing.");

        static byte[]? TryRead(string path)
        {
            try
            {
                return File.ReadAllBytes(path);
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }
    }

    private sealed class OtherProtector : IKeyProtector
    {
        public string Id => "other";

        public byte[] Protect(byte[] plaintext) => [.. plaintext.Reverse()];

        public byte[] Unprotect(byte[] protectedData) => [.. protectedData.Reverse()];
    }
}
