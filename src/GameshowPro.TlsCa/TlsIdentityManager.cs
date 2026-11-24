namespace GameshowPro.TlsCa;

/// <summary>
/// Owns one device identity for its whole life: creates it on first run, loads it afterwards, renews the leaf and
/// resets the identity on request, and hands the TLS server the current certificate.
/// </summary>
/// <remarks>
/// <para>
/// Time: every issuing operation uses the <see cref="TimeProvider"/>'s clock, floored at
/// <see cref="TlsCaOptions.MinimumTime"/>. Nothing else reads the clock.
/// </para>
/// <para>
/// Naming: the name is computed once, when the identity is created, and stored. If the machine is renamed later, the
/// stored name stays in force (certificates still match) and <see cref="NameMismatch"/> reports the name the machine
/// would get today; only <see cref="ResetIdentity"/> adopts it.
/// </para>
/// <para>
/// Thread safety: operations that change the identity run one at a time. Readers see an immutable snapshot that is
/// replaced in one step, so they never observe a half-updated identity. A server certificate that is replaced stays
/// usable for a grace period before it is disposed, so a TLS handshake that selected it just before the swap
/// completes normally.
/// </para>
/// </remarks>
public sealed partial class TlsIdentityManager : IDisposable
{
    private readonly IIdentityStore _store;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger _logger;
    private readonly Func<string> _hostName;
    private readonly string? _explicitName;
    private readonly string _appLabel;
    private readonly DateTimeOffset _minimumTime;
    private readonly TimeSpan _renewWhenRemaining;
    private readonly Func<X509Certificate2, ECDsa, X509Certificate2> _createServerCertificate;
    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly Lock _retiredLock = new();
    private ImmutableList<RetiredCertificate> _retired = [];
    private volatile ActiveIdentity? _active;
    private volatile bool _disposed;

    /// <summary>Creates a manager. Call <see cref="LoadOrCreate"/> before serving.</summary>
    /// <param name="options">Naming, time and renewal settings. They are read once, here.</param>
    /// <param name="store">Where the identity is kept, normally a <see cref="FileIdentityStore"/>.</param>
    /// <param name="timeProvider">The clock, normally <see cref="TimeProvider.System"/>.</param>
    /// <param name="logger">Receives lifecycle messages, which never include key material.</param>
    public TlsIdentityManager(TlsCaOptions options, IIdentityStore store, TimeProvider timeProvider, ILogger<TlsIdentityManager>? logger = null)
        : this(options, store, timeProvider, logger, static () => Environment.MachineName)
    {
    }

    /// <summary>Test constructor: <paramref name="hostName"/> replaces the system host name.</summary>
    internal TlsIdentityManager(TlsCaOptions options, IIdentityStore store, TimeProvider timeProvider, ILogger? logger, Func<string> hostName)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(hostName);
        if (options.ExplicitName is { } explicitName)
        {
            if (!DeviceName.IsValidLabel(explicitName))
            {
                throw new ArgumentException("TlsCaOptions.ExplicitName must be a valid device name (a-z, 0-9 and -, at most 63 characters).", nameof(options));
            }
        }
        else if (string.IsNullOrWhiteSpace(options.AppLabel))
        {
            throw new ArgumentException("Set TlsCaOptions.AppLabel, or TlsCaOptions.ExplicitName.", nameof(options));
        }

        if (options.RenewWhenRemaining <= TimeSpan.Zero || options.RenewWhenRemaining >= CertificateProfiles.LeafLifetime)
        {
            throw new ArgumentException("TlsCaOptions.RenewWhenRemaining must be positive and shorter than the leaf lifetime.", nameof(options));
        }

        _store = store;
        _timeProvider = timeProvider;
        _logger = logger ?? NullLogger.Instance;
        _hostName = hostName;
        _explicitName = options.ExplicitName;
        _appLabel = options.AppLabel;
        _minimumTime = options.MinimumTime;
        _renewWhenRemaining = options.RenewWhenRemaining;
        _createServerCertificate = options.ServerCertificateFactoryOverride ?? ServerCertificateFactory.Create;

        // Fails now, rather than at first use, when the app label cannot form a name.
        _ = DerivedName();
    }

    /// <summary>
    /// Raised after the identity in force changes (loaded, created, renewed or reset), outside the manager's lock, so a
    /// handler may call back into the manager. A handler's exception is logged and does not affect the operation.
    /// </summary>
    public event EventHandler<TlsIdentityChangedEventArgs>? Changed;

    /// <summary>True once <see cref="LoadOrCreate"/> (or <see cref="ResetIdentity"/>) has completed.</summary>
    public bool IsLoaded => _active is not null;

    /// <summary>The identity in force.</summary>
    /// <exception cref="InvalidOperationException">No identity has been loaded yet.</exception>
    public TlsIdentity Current => Active.Identity;

    /// <summary>
    /// The certificate for the TLS server: the leaf with its private key and no other certificate, so only the leaf is
    /// sent. Read it for every handshake (for example from Kestrel's <c>ServerCertificateSelector</c>) so a renewed or
    /// reset identity is served without a restart. Do not dispose it; the manager does, after a grace period once it
    /// has been replaced.
    /// </summary>
    /// <exception cref="InvalidOperationException">No identity has been loaded yet.</exception>
    public X509Certificate2 CurrentServerCertificate => Active.ServerCertificate;

    /// <summary>
    /// The device name the machine would get today, when it differs from the stored name; otherwise null. The stored
    /// name stays in force until <see cref="ResetIdentity"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">No identity has been loaded yet.</exception>
    public string? NameMismatch => NameMismatchFor(Current);

    /// <summary>
    /// How long a replaced server certificate stays usable before it is disposed: well beyond any TLS handshake timeout
    /// (Kestrel's default is 10 seconds). Settable for tests.
    /// </summary>
    internal TimeSpan RetiredCertificateGrace { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>The identity in force, or null when none is loaded (not yet, it could not be, or the manager is disposed). Never throws.</summary>
    internal TlsIdentity? CurrentOrDefault => _active?.Identity;

    /// <summary>The server certificate in force, or null when no identity is loaded. Never throws; see <see cref="CurrentServerCertificate"/>.</summary>
    internal X509Certificate2? CurrentServerCertificateOrDefault => _active?.ServerCertificate;

    /// <summary>
    /// Why the last <see cref="LoadOrCreate"/> failed (the <see cref="IdentityStoreException"/> message, which holds no key
    /// material), or null when it has not failed. It is not cleared by a later success; check <see cref="IsLoaded"/> first.
    /// </summary>
    internal string? LoadFailure { get; private set; }

    /// <summary>The name the machine would get today when it differs from <paramref name="identity"/>'s name, else null.</summary>
    internal string? NameMismatchFor(TlsIdentity identity)
    {
        string today = DerivedName();
        return today == identity.Name ? null : today;
    }

    private ActiveIdentity Active
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _active ?? throw new InvalidOperationException("The TLS identity has not been loaded yet; call LoadOrCreate first.");
        }
    }

    /// <summary>
    /// Loads the stored identity, or creates one if none is stored (first run): the device name, a new CA and a new
    /// leaf, saved before they are used. Loading regenerates nothing. Later calls return the identity in force.
    /// </summary>
    /// <exception cref="IdentityStoreException">
    /// An identity is stored but cannot be used. A new identity is never created in its place; recovery is to restore
    /// access to it or to call <see cref="ResetIdentity"/>.
    /// </exception>
    public async ValueTask<TlsIdentity> LoadOrCreate(CancellationToken cancellationToken = default)
    {
        TlsIdentityChangedEventArgs change;
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_active is { } loaded)
            {
                return loaded.Identity;
            }

            using StoredIdentity? stored = LoadFromStore();
            if (stored is null)
            {
                ActiveIdentity created;
                try
                {
                    created = await CreateAndSave(DerivedName(), previousCaFingerprint: null, cancellationToken).ConfigureAwait(false);
                }
                catch (IdentityStoreException exception)
                {
                    LoadFailure = exception.Message;
                    LogCreateFailed(exception);
                    throw;
                }

                Install(created);
                LogCreated(created.Identity.MdnsName, created.Identity.CaFingerprintSha256);
                change = new(created.Identity, TlsIdentityChange.Created);
            }
            else
            {
                ActiveIdentity active;
                try
                {
                    active = Activate(stored);
                }
                catch (IdentityStoreException exception)
                {
                    LoadFailure = exception.Message;
                    LogStoreUnusable(exception);
                    throw;
                }

                Install(active);
                LogLoaded(active.Identity.MdnsName, active.Identity.CaFingerprintSha256, active.Identity.LeafNotAfter);
                change = new(active.Identity, TlsIdentityChange.Loaded);
                string today = DerivedName();
                if (today != active.Identity.Name)
                {
                    LogNameMismatch(today, active.Identity.Name);
                }
            }
        }
        finally
        {
            _ = _operationGate.Release();
        }

        RaiseChanged(change);
        return change.Identity;

        StoredIdentity? LoadFromStore()
        {
            try
            {
                return _store.Load();
            }
            catch (IdentityStoreException exception)
            {
                LoadFailure = exception.Message;
                LogStoreUnusable(exception);
                throw;
            }
        }
    }

    /// <summary>
    /// Issues a new leaf, with a new key, under the existing CA. Clients that trust the CA are not affected. The new
    /// leaf is saved before it is served.
    /// </summary>
    /// <exception cref="InvalidOperationException">No identity has been loaded yet.</exception>
    /// <exception cref="ArgumentException">The CA has expired; only a reset can help.</exception>
    /// <exception cref="IdentityStoreException">The renewed identity could not be saved; the previous one stays in force.</exception>
    public async ValueTask<TlsIdentity> RenewLeaf(CancellationToken cancellationToken = default)
    {
        TlsIdentityChangedEventArgs change;
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            change = await RenewCore(Active, Now(), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = _operationGate.Release();
        }

        RaiseChanged(change);
        return change.Identity;
    }

    /// <summary>
    /// Renews the leaf when less than <see cref="TlsCaOptions.RenewWhenRemaining"/> of its validity remains. A leaf that
    /// already ends with the CA cannot be extended; that is logged as a warning (a reset is needed) and not renewed.
    /// </summary>
    /// <returns>True when the leaf was renewed.</returns>
    /// <exception cref="InvalidOperationException">No identity has been loaded yet.</exception>
    /// <exception cref="IdentityStoreException">The renewed identity could not be saved; the previous one stays in force.</exception>
    public async ValueTask<bool> RenewIfDue(CancellationToken cancellationToken = default)
    {
        TlsIdentityChangedEventArgs change;
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ActiveIdentity active = Active;
            TlsIdentity current = active.Identity;
            DateTimeOffset now = Now();
            if (current.LeafNotAfter - now >= _renewWhenRemaining)
            {
                return false;
            }

            if (current.LeafNotAfter >= current.CaNotAfter)
            {
                LogCaExpiring(current.MdnsName, current.CaNotAfter);
                return false;
            }

            change = await RenewCore(active, now, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = _operationGate.Release();
        }

        RaiseChanged(change);
        return true;
    }

    /// <summary>
    /// Replaces the identity with a new CA and leaf, under the name the machine would get today, and records the
    /// previous CA fingerprint. Every client must install the new CA certificate. This also works when the stored
    /// identity could not be loaded: it is then replaced, and its fingerprint is recorded only if the store can still
    /// read it.
    /// </summary>
    /// <exception cref="IdentityStoreException">The new identity could not be saved; the previous one stays in force.</exception>
    public async ValueTask<TlsIdentity> ResetIdentity(CancellationToken cancellationToken = default)
    {
        TlsIdentityChangedEventArgs change;
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            string? previousCaFingerprint = _active?.Identity.CaFingerprintSha256 ?? TryReadStoredCaFingerprint();
            ActiveIdentity reset = await CreateAndSave(DerivedName(), previousCaFingerprint, cancellationToken).ConfigureAwait(false);
            Install(reset);
            LogReset(reset.Identity.MdnsName, reset.Identity.CaFingerprintSha256, previousCaFingerprint ?? "none");
            change = new(reset.Identity, TlsIdentityChange.Reset);
        }
        finally
        {
            _ = _operationGate.Release();
        }

        RaiseChanged(change);
        return change.Identity;

        string? TryReadStoredCaFingerprint()
        {
            try
            {
                using StoredIdentity? stored = _store.Load();
                return stored is null ? null : Fingerprint.Sha256(stored.CaCertificateDer);
            }
            catch (IdentityStoreException)
            {
                return null;
            }
        }
    }

    /// <summary>Disposes every certificate and key immediately. Stop the TLS server first.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _operationGate.Wait();
        try
        {
            if (_disposed)
            {
                return;
            }

            RetiredCertificate[] retired;
            lock (_retiredLock)
            {
                _disposed = true;
                retired = [.. _retired];
                _retired = [];
            }

            foreach (RetiredCertificate entry in retired)
            {
                entry.Dispose();
            }

            _active?.Dispose();
            _active = null;
        }
        finally
        {
            _ = _operationGate.Release();
        }
    }

    /// <summary>The name a new identity gets today: the explicit name, or the host name plus the app label.</summary>
    private string DerivedName() => _explicitName ?? DeviceName.Derive(_hostName(), _appLabel);

    /// <summary>The issuance time: the clock, floored at the minimum time.</summary>
    private DateTimeOffset Now()
    {
        DateTimeOffset clock = _timeProvider.GetUtcNow();
        if (clock >= _minimumTime)
        {
            return clock;
        }

        LogClockBeforeMinimum(clock, _minimumTime);
        return _minimumTime;
    }

    /// <summary>Creates a CA and a leaf for <paramref name="name"/>, and saves them. The gate must be held.</summary>
    private async ValueTask<ActiveIdentity> CreateAndSave(string name, string? previousCaFingerprint, CancellationToken cancellationToken)
    {
        DateTimeOffset now = Now();
        try
        {
            using ECDsa caKey = CertificateProfiles.CreateKey();
            using X509Certificate2 caCertificate = CertificateProfiles.CreateCa(name, caKey, now);
            using IssuedLeaf leaf = await new LocalLeafIssuer(caCertificate, caKey).Issue(now, cancellationToken).ConfigureAwait(false);
            using StoredIdentity stored = new()
            {
                Name = name,
                CaCertificateDer = caCertificate.RawData,
                CaPrivateKeyPkcs8 = caKey.ExportPkcs8PrivateKey(),
                LeafCertificateDer = leaf.Certificate.RawData,
                LeafPrivateKeyPkcs8 = leaf.Key.ExportPkcs8PrivateKey(),
                PreviousCaFingerprintSha256 = previousCaFingerprint,
            };
            return ActivateAndSave(stored);
        }
        catch (CryptographicException exception)
        {
            // Activation and saving report their own failures as IdentityStoreException; this is key generation or signing.
            throw GenerationFailed("A new TLS identity could not be generated", exception);
        }
    }

    /// <summary>Issues a new leaf under the active CA, saves it and installs it. The gate must be held.</summary>
    private async ValueTask<TlsIdentityChangedEventArgs> RenewCore(ActiveIdentity active, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ActiveIdentity renewed;
        try
        {
            // The issuer reads the name from the stored CA certificate; the stored name is checked against it on activation.
            using IssuedLeaf leaf = await new LocalLeafIssuer(active.CaCertificate, active.CaKey).Issue(now, cancellationToken).ConfigureAwait(false);
            using StoredIdentity stored = new()
            {
                Name = active.Identity.Name,
                CaCertificateDer = active.CaCertificate.RawData,
                CaPrivateKeyPkcs8 = active.CaKey.ExportPkcs8PrivateKey(),
                LeafCertificateDer = leaf.Certificate.RawData,
                LeafPrivateKeyPkcs8 = leaf.Key.ExportPkcs8PrivateKey(),
                PreviousCaFingerprintSha256 = active.Identity.PreviousCaFingerprintSha256,
            };
            renewed = ActivateAndSave(stored);
        }
        catch (CryptographicException exception)
        {
            throw GenerationFailed("A new TLS leaf could not be generated", exception);
        }

        Install(renewed);
        LogRenewed(renewed.Identity.MdnsName, renewed.Identity.LeafNotAfter);
        return new(renewed.Identity, TlsIdentityChange.Renewed);
    }

    private static IdentityStoreException GenerationFailed(string what, CryptographicException innerException) =>
        new($"{what} ({innerException.GetType().Name}). The identity in force, if any, is unchanged.", innerException);

    /// <summary>
    /// Builds the in-memory identity from <paramref name="stored"/> first (which proves it is consistent and servable),
    /// then saves it. Nothing is saved that could not be served.
    /// </summary>
    private ActiveIdentity ActivateAndSave(StoredIdentity stored)
    {
        ActiveIdentity active = Activate(stored);
        try
        {
            _store.Save(stored);
            return active;
        }
        catch
        {
            active.Dispose();
            throw;
        }
    }

    /// <summary>Makes <paramref name="next"/> the identity in force and retires the previous one.</summary>
    private void Install(ActiveIdentity next)
    {
        ActiveIdentity? previous = _active;
        _active = next;
        if (previous is not null)
        {
            // The CA objects are only used under the gate, which is held; the server certificate may be in a handshake.
            previous.DisposeSigningMaterial();
            Retire(previous.ServerCertificate);
        }

        void Retire(X509Certificate2 certificate)
        {
            lock (_retiredLock)
            {
                if (_disposed)
                {
                    certificate.Dispose();
                    return;
                }

                RetiredCertificate entry = new(certificate);
                _retired = _retired.Add(entry);
                // Created under the lock, so the callback (which takes the lock) always sees the timer assigned.
                entry.Timer = _timeProvider.CreateTimer(
                    DisposeRetiredOnTimer,
                    (this, entry),
                    RetiredCertificateGrace,
                    Timeout.InfiniteTimeSpan);
            }

            static void DisposeRetiredOnTimer(object? state)
            {
                (TlsIdentityManager manager, RetiredCertificate retired) = ((TlsIdentityManager, RetiredCertificate))state!;
                lock (manager._retiredLock)
                {
                    if (!manager._retired.Contains(retired))
                    {
                        return;
                    }

                    manager._retired = manager._retired.Remove(retired);
                }

                retired.Dispose();
            }
        }
    }

    private void RaiseChanged(TlsIdentityChangedEventArgs change)
    {
        if (Changed is not { } handlers)
        {
            return;
        }

        foreach (EventHandler<TlsIdentityChangedEventArgs> handler in handlers.GetInvocationList().Cast<EventHandler<TlsIdentityChangedEventArgs>>())
        {
            try
            {
                handler(this, change);
            }
#pragma warning disable CA1031 // A subscriber's failure must not surface as a failure of an operation that has already completed.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogChangedHandlerFailed(exception);
            }
        }
    }

    /// <summary>
    /// Decodes and cross-checks a stored identity and builds the server certificate. Every failure is an
    /// <see cref="IdentityStoreException"/> without key material, with the cause as its inner exception.
    /// </summary>
    private ActiveIdentity Activate(StoredIdentity stored)
    {
        X509Certificate2? caCertificate = null;
        ECDsa? caKey = null;
        X509Certificate2? leafCertificate = null;
        ECDsa? leafKey = null;
        X509Certificate2? serverCertificate = null;
        try
        {
            if (!DeviceName.IsValidLabel(stored.Name))
            {
                throw Inconsistent("the device name is not a valid DNS label");
            }

            caCertificate = LoadCertificate(stored.CaCertificateDer, "CA certificate");
            if (!caCertificate.SubjectName.RawData.AsSpan().SequenceEqual(CertificateProfiles.CaSubject(stored.Name).RawData))
            {
                throw Inconsistent("the CA certificate does not belong to the stored device name");
            }

            caKey = ImportKey(stored.CaPrivateKeyPkcs8, "CA private key");
            if (!MatchesPublicKey(caKey, caCertificate))
            {
                throw Inconsistent("the CA private key does not match the CA certificate");
            }

            leafCertificate = LoadCertificate(stored.LeafCertificateDer, "leaf certificate");
            if (!leafCertificate.IssuerName.RawData.AsSpan().SequenceEqual(caCertificate.SubjectName.RawData)
                || !leafCertificate.SubjectName.RawData.AsSpan().SequenceEqual(CertificateProfiles.LeafSubject(stored.Name).RawData)
                || !IsSignedBy(leafCertificate, caKey))
            {
                throw Inconsistent("the leaf certificate was not issued by the stored CA for the stored device name");
            }

            leafKey = ImportKey(stored.LeafPrivateKeyPkcs8, "leaf private key");
            if (!MatchesPublicKey(leafKey, leafCertificate))
            {
                throw Inconsistent("the leaf private key does not match the leaf certificate");
            }

            serverCertificate = CreateServerCertificate(leafCertificate, leafKey);
            TlsIdentity identity = new(stored.Name, [.. stored.CaCertificateDer], [.. stored.LeafCertificateDer], stored.PreviousCaFingerprintSha256);
            ActiveIdentity active = new(identity, caCertificate, caKey, serverCertificate);
            // Ownership has moved to the active identity.
            caCertificate = null;
            caKey = null;
            serverCertificate = null;
            return active;
        }
        catch (CryptographicException exception)
        {
            // Anything not already reported above (a key that cannot be exported for comparison, a signature check that
            // fails to run): the identity cannot be used either way.
            throw new IdentityStoreException(
                $"The TLS identity could not be activated ({exception.GetType().Name}). A new identity is not created automatically; "
                + "reset the identity explicitly to replace it.", exception);
        }
        finally
        {
            caCertificate?.Dispose();
            caKey?.Dispose();
            leafCertificate?.Dispose();
            leafKey?.Dispose();
            serverCertificate?.Dispose();
        }

        // The platform step most likely to fail on a healthy file: on Windows the leaf key is imported into a key container in
        // the account's profile, which an account without a loaded profile (some service accounts) may not have.
        X509Certificate2 CreateServerCertificate(X509Certificate2 leaf, ECDsa key)
        {
            try
            {
                return _createServerCertificate(leaf, key);
            }
#pragma warning disable CA1031 // Whatever the platform throws, the identity cannot be served; the cause is kept as the inner exception.
            catch (Exception exception) when (exception is not (OperationCanceledException or ObjectDisposedException or IdentityStoreException))
#pragma warning restore CA1031
            {
                throw new IdentityStoreException(
                    $"The TLS server certificate could not be prepared for serving ({exception.GetType().Name}). On Windows its "
                    + "private key is imported into a key container in the user profile of the account running this app, so "
                    + "that account needs a profile it can load. The identity in force, if any, is unchanged.", exception);
            }
        }

        static X509Certificate2 LoadCertificate(byte[] der, string what)
        {
            try
            {
                return X509CertificateLoader.LoadCertificate(der);
            }
            catch (CryptographicException exception)
            {
                throw Inconsistent($"the {what} cannot be decoded", exception);
            }
        }

        static ECDsa ImportKey(byte[] pkcs8, string what)
        {
            ECDsa key = ECDsa.Create();
            try
            {
                key.ImportPkcs8PrivateKey(pkcs8, out int bytesRead);
                if (bytesRead != pkcs8.Length)
                {
                    throw Inconsistent($"the {what} has trailing data");
                }

                return key;
            }
            catch (CryptographicException exception)
            {
                key.Dispose();
                throw Inconsistent($"the {what} cannot be decoded", exception);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }

        static bool MatchesPublicKey(ECDsa key, X509Certificate2 certificate) =>
            key.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(certificate.PublicKey.ExportSubjectPublicKeyInfo());

        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }; every certificate
        // here is signed with ECDSA and SHA-256.
        static bool IsSignedBy(X509Certificate2 certificate, ECDsa issuerKey)
        {
            try
            {
                AsnReader reader = new(certificate.RawDataMemory, AsnEncodingRules.DER);
                AsnReader fields = reader.ReadSequence();
                ReadOnlyMemory<byte> toBeSigned = fields.ReadEncodedValue();
                _ = fields.ReadEncodedValue();
                byte[] signature = fields.ReadBitString(out int unusedBitCount);
                return unusedBitCount == 0
                    && issuerKey.VerifyData(toBeSigned.Span, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            }
            catch (AsnContentException)
            {
                return false;
            }
        }

        static IdentityStoreException Inconsistent(string reason, Exception? innerException = null)
        {
            string message = $"The stored TLS identity is inconsistent: {reason}. A new identity is not created automatically, "
                + "because that would break every client's trust in this device; reset the identity explicitly to replace it.";
            return innerException is null ? new(message) : new(message, innerException);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Created the TLS identity for {MdnsName}. CA fingerprint (SHA-256): {CaFingerprint}")]
    private partial void LogCreated(string mdnsName, string caFingerprint);

    [LoggerMessage(Level = LogLevel.Information, Message = "Loaded the TLS identity for {MdnsName}. CA fingerprint (SHA-256): {CaFingerprint}. Leaf valid until {LeafNotAfter:u}")]
    private partial void LogLoaded(string mdnsName, string caFingerprint, DateTimeOffset leafNotAfter);

    [LoggerMessage(Level = LogLevel.Warning, Message = "This machine's device name is now {CurrentName}, but the TLS identity is for {StoredName}. The stored name stays in force; reset the identity to adopt the new name.")]
    private partial void LogNameMismatch(string currentName, string storedName);

    [LoggerMessage(Level = LogLevel.Information, Message = "Renewed the TLS leaf for {MdnsName}; valid until {LeafNotAfter:u}")]
    private partial void LogRenewed(string mdnsName, DateTimeOffset leafNotAfter);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Reset the TLS identity for {MdnsName}. New CA fingerprint (SHA-256): {CaFingerprint}; previous: {PreviousCaFingerprint}. Every client must install the new CA certificate.")]
    private partial void LogReset(string mdnsName, string caFingerprint, string previousCaFingerprint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The TLS leaf for {MdnsName} cannot be renewed beyond its CA, which expires at {CaNotAfter:u}. Reset the identity before then.")]
    private partial void LogCaExpiring(string mdnsName, DateTimeOffset caNotAfter);

    [LoggerMessage(Level = LogLevel.Warning, Message = "The system clock ({Clock:u}) is earlier than the minimum time ({MinimumTime:u}); issuing at the minimum time.")]
    private partial void LogClockBeforeMinimum(DateTimeOffset clock, DateTimeOffset minimumTime);

    [LoggerMessage(Level = LogLevel.Error, Message = "The stored TLS identity cannot be used. No new identity was created.")]
    private partial void LogStoreUnusable(Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "The first TLS identity could not be created or saved. No identity is in force.")]
    private partial void LogCreateFailed(Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "A TLS identity Changed handler failed.")]
    private partial void LogChangedHandlerFailed(Exception exception);

    /// <summary>The identity in force with the live objects behind it.</summary>
    private sealed class ActiveIdentity(TlsIdentity identity, X509Certificate2 caCertificate, ECDsa caKey, X509Certificate2 serverCertificate) : IDisposable
    {
        public TlsIdentity Identity { get; } = identity;

        public X509Certificate2 CaCertificate { get; } = caCertificate;

        public ECDsa CaKey { get; } = caKey;

        public X509Certificate2 ServerCertificate { get; } = serverCertificate;

        public void DisposeSigningMaterial()
        {
            CaKey.Dispose();
            CaCertificate.Dispose();
        }

        public void Dispose()
        {
            DisposeSigningMaterial();
            ServerCertificate.Dispose();
        }
    }

    /// <summary>A replaced server certificate waiting out its grace period.</summary>
    private sealed class RetiredCertificate(X509Certificate2 certificate) : IDisposable
    {
        public ITimer? Timer { get; set; }

        public void Dispose()
        {
            Timer?.Dispose();
            certificate.Dispose();
        }
    }
}
