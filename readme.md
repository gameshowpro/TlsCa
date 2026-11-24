# GameshowPro.TlsCa

HTTPS on offline LANs for GameshowPro applications. Each installation is its own small certificate authority, name-constrained so that it can vouch only for its own `.local` name. A user installs that one CA certificate, downloaded from the app, and from then on `https://<name>.local:<port>/` loads without a warning. Nothing is shared between installations, and no key material is ever part of the package, an installer or the app directory: keys are generated on the machine that uses them.

The same trust model, certificate profiles and well-known endpoints are used by the GameshowPro ESP32 firmware, so every product gives users the same experience.

## Certificate core

The library has three layers, each described below: the certificate core, the identity lifecycle, and the ASP.NET Core integration (endpoints, management page, mDNS advertisement) that most apps use on its own.

```csharp
// GlobalUsings.cs
global using System.Security.Cryptography;
global using System.Security.Cryptography.X509Certificates;
global using GameshowPro.TlsCa;

string name = DeviceName.Derive(Environment.MachineName, "triggergate"); // "studio-pc-triggergate"
DateTimeOffset now = DateTimeOffset.UtcNow;

using ECDsa caKey = CertificateProfiles.CreateKey();
using X509Certificate2 ca = CertificateProfiles.CreateCa(name, caKey, now);

using ECDsa leafKey = CertificateProfiles.CreateKey();
using X509Certificate2 leaf = CertificateProfiles.CreateLeaf(name, ca, caKey, leafKey, now);

string fingerprint = Fingerprint.Sha256(ca); // "AB:CD:..."
```

- `DeviceName.Derive(host, app)` returns `<host>-<app>`: lower-case, characters outside `a-z0-9-` replaced by `-`, runs collapsed, leading and trailing hyphens trimmed. When the result would exceed 63 characters the host part is truncated; an empty host part becomes `gsp`.
- `CertificateProfiles.CreateCa` makes the self-signed device CA: `CN=GameshowPro Device CA <name>, O=GameshowPro`, ECDSA P-256 with SHA-256, a random positive 128-bit serial, valid from the issuance time minus 48 hours for 20 years, with critical basicConstraints (CA, path length 0), critical keyUsage (keyCertSign), critical nameConstraints (permitted dNSName `<name>.local`, excluded IP addresses `0.0.0.0/0` and `::/0`), extendedKeyUsage serverAuth and a subject key identifier.
- `CertificateProfiles.CreateLeaf` makes the leaf for `<name>.local` only: valid from the issuance time minus 48 hours for 800 days, critical basicConstraints (not a CA), critical keyUsage (digitalSignature), extendedKeyUsage serverAuth, a subject alternative name holding exactly one dNSName, and an authority key identifier matching the CA. It takes the device name, never arbitrary names.
- The issuance time is always a parameter; nothing reads the clock.
- In the CA's final 800 days a leaf's notAfter is clamped to the CA's notAfter, so a leaf never outlives its CA.
- Returned certificates carry no private key. `ILeafIssuer` (`Issue(now, cancellationToken)`) is the single seam for leaf issuance; `LocalLeafIssuer` signs with the stored CA key and reads the device name from the stored CA certificate.
- `Fingerprint.Sha256` formats a certificate's SHA-256 hash as upper-case hex pairs joined by `:`.

## Identity lifecycle

```csharp
TlsCaOptions options = new() { Product = "TriggerGate", AppLabel = "triggergate", StorageDirectory = directory };
FileIdentityStore store = new(options.StorageDirectory, FileIdentityStore.DefaultKeyProtector());
using TlsIdentityManager manager = new(options, store, TimeProvider.System, logger);

TlsIdentity identity = await manager.LoadOrCreate();  // first run: creates; afterwards: loads, regenerates nothing
X509Certificate2 serverCertificate = manager.CurrentServerCertificate; // read per handshake; leaf only
await manager.RenewIfDue();                            // new leaf under the same CA when < 90 days remain
```

- `TlsIdentityManager.LoadOrCreate` creates the identity on first run (name from `DeviceName.Derive(Environment.MachineName, AppLabel)`, or `ExplicitName`) and loads it afterwards. `RenewLeaf` issues a new leaf key and certificate under the same CA; `ResetIdentity` creates a new CA and leaf under the name the machine would get today and records the previous CA fingerprint; `RenewIfDue` renews when less than `RenewWhenRemaining` (90 days) remains. `Changed` is raised after each change.
- The stored name stays in force if the machine is renamed; `NameMismatch` reports the name it would get today. Only a reset adopts it.
- Time is the `TimeProvider`'s clock floored at `TlsCaOptions.MinimumTime`, which defaults to the library's build time.
- Thread-safe: changes run one at a time and readers see an immutable `TlsIdentity` snapshot. A replaced server certificate stays usable for two minutes, so a handshake that selected it completes, and is then disposed.
- On Windows the server certificate's key is imported into a key container in the current account's profile, because SChannel cannot use an in-memory key; the container is deleted when the certificate is disposed. Dispose the manager on shutdown. Elsewhere the key stays in memory.
- `FileIdentityStore` keeps one JSON file, `identity.json`, written atomically (temporary file in the same directory, flushed, then renamed over the old one). Private keys are PKCS#8 protected by an `IKeyProtector`: `DpapiKeyProtector` (machine scope) on Windows, `PassthroughKeyProtector` elsewhere. Before the first key is written, the directory is restricted: on Windows an ACL without inheritance granting full control to SYSTEM, Administrators and the current account only; elsewhere mode 0700 for the directory and 0600 for the file.
- A missing file means "no identity yet". An unreadable, corrupt, inconsistent or undecryptable file raises `IdentityStoreException` with a clear message and never leads to a new identity, because that would break every client's trust. `LoadOrCreate` logs it as an error and throws; so does a first identity that cannot be saved. Platform failures are reported the same way, with the platform's exception as the inner exception: a key protector that fails to protect or unprotect (for example DPAPI unavailable to the account), a server certificate that cannot be prepared (on Windows, an account without a loadable user profile for the key container), and key generation or signing that fails. A renew or reset that fails in any of these ways leaves the identity in force, in memory and on disk. Cancellation, invalid arguments (including renewing under an expired CA) and use after disposal are not wrapped. Recovery is to restore access or to call `ResetIdentity`, which works with nothing loaded. (The ASP.NET Core integration keeps the app running in that case; see "When the identity cannot be used" below.)
- No key material appears in logs or exception messages.

## Using it in an app

Two calls, made unconditionally:

```csharp
// GlobalUsings.cs
global using GameshowPro.TlsCa;
global using GameshowPro.TlsCa.AspNetCore;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);   // CreateSlimBuilder works too (Native AOT)
builder.WebHost.UseUrls("http://*:9090");          // the app declares its plain-HTTP port as it always did
TlsCaMode mode = builder.AddGameshowProTlsCa(options =>
{
    options.Product = "TriggerGate";               // shown to users, carried in info.json
    options.AppLabel = "triggergate";              // device name: <host>-<app>, e.g. studio-pc-triggergate.local
    options.HttpPort = 9090;                       // advertised over mDNS (and bound if the app declared no URLs)
    options.HttpsPort = 9190;                      // the default; registry convention: HTTP port + 100
    options.ConfigurationSection = "TriggerGate";  // TriggerGate:HttpsPort, TriggerGate:CertificatePath, ... override
});

WebApplication app = builder.Build();
app.UseGameshowProTlsCa();                         // early, before the app's own redirects, routing and fallback
// ... the app's own pipeline ...
app.Run();
```

**Choosing `HttpsPort`.** The library has no built-in default port: every app passes its own. GameshowPro apps follow the service port registry (`Docs/docs/service-port-registry.md`), which assigns each app's HTTPS port as its registered HTTP port + 100 (TriggerGate: HTTP 9090, HTTPS 9190). An appliance that owns its machine may use 443.

**Configuration section.** When `ConfigurationSection` is set, the library reads, after the `configure` callback:

| Key | Effect |
| --- | --- |
| `<section>:HttpsPort` | Overrides `HttpsPort`. `0` turns HTTPS off. Anything else outside 1 to 65535, or not a number, throws `InvalidOperationException` naming the key. Blank is ignored. |
| `<section>:TlsStorageDirectory` | Overrides `StorageDirectory`. Blank is ignored. |
| `<section>:CertificatePath` | Overrides `CertificatePath`: the app's own certificate (see "Modes"). Blank is ignored. |
| `<section>:CertificateKeyPath` | Overrides `CertificateKeyPath`: the PEM private key, when it is in its own file. Blank is ignored. |
| `<section>:CertificatePassword` | Overrides `CertificatePassword`: the PKCS#12 password, or the password of an encrypted PEM key. Blank is ignored. |

For Soundling these are `Soundling__HttpsPort`, `Soundling__CertificatePath`, `Soundling__CertificateKeyPath` and `Soundling__CertificatePassword` as environment variables.

**Modes.** `AddGameshowProTlsCa` decides how HTTPS is provided and returns the `TlsCaMode`; the app makes the same two calls whatever the configuration says. The `configure` callback runs once on the options instance the library keeps; afterwards that instance holds the effective values (port, storage directory, absolute certificate paths, version), for an app's own checks. The mode, first match wins:

| Mode | When | What the library does |
| --- | --- | --- |
| `Off` | The effective `HttpsPort` is `0` | No HTTPS listener. |
| `OwnCertificate` | `CertificatePath` is set | Loads that certificate and serves it on `HttpsPort` (see "Using your own certificate"). |
| `KestrelCertificate` | `Kestrel:Certificates:Default:Path` is set, or any `Kestrel:Endpoints:<name>:Url` is an `https` URL (`TlsCaConfiguration.HasExternalCertificate`) | No listener at all: Kestrel serves its configured certificate, and fails as it always did when that certificate is wrong. One Information line says so. |
| `BuiltInCa` | Otherwise | The per-installation CA, as described in the rest of this section. |

Plain-HTTP `Kestrel:Endpoints` do not count as a certificate; Kestrel binds them and the library adds its HTTPS listener next to them. When `CertificatePath` is set and Kestrel also configures a certificate, a warning names both settings: the library serves its file on `HttpsPort` and Kestrel serves its own endpoint separately (two listeners, which fail to bind if they share a port). An invalid `<section>:HttpsPort` throws in every mode, and `CertificateKeyPath` without `CertificatePath` throws `ArgumentException`.

In every mode other than `BuiltInCa`: no CA is created or loaded and the storage directory is not touched; there is no renewal, mDNS advertisement or HTTP root redirect; `ITlsCaStatus` and the well-known prefix are still there (see "Without the built-in CA" below). In `Off` and `OwnCertificate` the app's plain-HTTP listeners are handled as in `BuiltInCa` (see "HTTP and HTTPS together"); in `KestrelCertificate` nothing is added.

**`UseGameshowProTlsCa`** serves the well-known prefix in every mode, and throws `InvalidOperationException` when `AddGameshowProTlsCa` was not called:

- Every request under `/.well-known/gameshowpro`, on every listener, is answered by the library and goes no further, whatever the app's own routing, redirects or fallback would do. An unknown path there gets 404.
- In `BuiltInCa` only, with `RedirectHttpRoot` (default true), a plain-HTTP `GET` or `HEAD` of `/` whose `Host` is not `localhost`, `127.0.0.1` or `[::1]` (`LoopbackGate.IsLoopbackHost`) gets `302` with `Cache-Control: no-store` to `http://<host>/.well-known/gameshowpro/`, keeping the `Host` port and the query string. Without a `Host` header the local address the request arrived on is used, and 404 if that is unknown. HTTPS, other paths, other methods and loopback hosts continue down the pipeline: `http://localhost:<port>/` is already a secure context, so the app serves its UI there.

`MapGameshowProTlsCa` (endpoint routing) remains for apps that prefer it; it requires `AddGameshowProTlsCa`.

In `BuiltInCa`, the two calls register the `TlsIdentityManager` as a singleton (the container disposes it at shutdown), load or create the identity before Kestrel binds (an identity that cannot be used does not stop the app; see below), add the HTTPS listener (serving `manager.CurrentServerCertificate` per handshake, so a renewed leaf needs no restart), renew the leaf at startup and every 24 hours when less than 90 days remain, and advertise `<name>.local` plus `_https._tcp` (TXT `path=/`) and `_http._tcp` (TXT `path=/.well-known/gameshowpro/`) over mDNS. An mDNS failure is logged and retried; it never stops the web server. A name conflict is reported in `info.json` (`nameConflict`), in `ITlsCaStatus` and in the log, and never resolved by renaming.

**Where mDNS advertises.** `TlsCaOptions.MdnsScopes` (`IReadOnlyList<TlsCaMdnsScope>?`) passes GameshowPro.Mdns's interface scope through. A `TlsCaMdnsScope(NetworkInterfaceId, LocalAddress)` is the pair Mdns takes together: a `NetworkInterface.Id` (not empty) and an IPv4 or IPv6 address of that interface, which is the only address the scope publishes.

- Null (the default): one advertisement on every interface Mdns finds eligible.
- Empty: nothing is advertised while the list stays empty (for example, the network the app was told to use is absent).
- Otherwise: one advertisement (the `_https._tcp` and `_http._tcp` pair, under the same name) per scope; duplicates count once. Each scope runs on its own: a scope whose interface or address is absent, or that fails to start for any other reason, is logged and retried every 30 seconds without stopping or delaying the others. `NameConflict` is true while any scope reports a conflict and clears when none does, including when the conflicting scope leaves the list.
- The list may be replaced from any thread while the app runs, on the options instance the library keeps (capture it in the `configure` callback, or resolve `TlsCaOptions` from DI). Within two seconds the scopes that left the list are withdrawn (with an mDNS goodbye) and new ones start; scopes still in the list keep running without a goodbye or a new probe. The setter copies the list, so set a new list rather than changing the one you passed. A name change after a reset restarts every scope, and nothing is advertised while there is no identity, as without scopes.
- Use one scope per interface. Two scopes on one interface with different addresses are not one address set to Mdns: each registration publishes its own cache-flush A/AAAA set for the name, so the sets replace each other in other devices' caches (and may be reported as a name conflict) rather than combine.
- Scopes affect mDNS only. The HTTPS listener the library adds still accepts connections on every interface, and so do the app's own listeners. Restricting who can connect is the app's job: bind its own endpoints to chosen addresses, or filter connections by their local address.

**Apps that already use GameshowPro.Mdns.** Nothing needs passing in, and there is no overload that takes an existing Mdns object. Mdns has one runtime per process that owns the sockets; `AdvertisedService`, `ServiceFinder` and `ConflictMonitor` are handles that register with it, so the library's advertisements run next to the app's own.

- Discovery and single-instance checks are not affected. The library advertises only `_https._tcp` and `_http._tcp`, with the device name as the instance name, so a `ConflictMonitor` or `ServiceFinder` for the app's own service type never sees them. A finder that browses `_http._tcp` or `_https._tcp` sees the library's entry only when its search profile allows this machine (`AllowLocalhost`).
- Two things collide, and both fail the later registration with "already owned by another local registration", which the library reports as a name conflict although no other device is involved. Do not advertise `_http._tcp` or `_https._tcp` yourself under the device name with a different port or TXT. Do not publish the device name as `HostName` with a different scope on a network the library also advertises on.
- An app advertisement may set `HostName` to the device name with the same scope as the library (the same `MdnsScopes` entry, or none when `MdnsScopes` is null). It then shares the library's address records, so the app's service resolves to the name the certificate is valid for.
- `ConflictMonitor` takes no scope: it advertises the app's service type on every interface whatever `MdnsScopes` says. An app that restricts its networks advertises with `AdvertisedService` and its own scope instead.
- An app that must own every advertisement sets `AdvertiseMdns = false` and publishes the name itself. `NameConflict` then stays false, because the library has nothing to observe.

The collisions and the shared `HostName` case are read from the Mdns registration code; the library's tests do not run them. Soundling runs its own service-type advertisement next to the library's with no conflict.

**Status for the app's own UI.** `ITlsCaStatus` (in DI in every mode) exposes `Mode`, `MdnsName`, `HttpsPort`, `NameConflict`, `NameMismatch`, `CaFingerprintSha256`, `IdentityProblem`, `Problem`, `CertificateNotAfter` and `CertificateDnsNames`, and raises `Changed` after a renewal, a reset, a change in the name conflict, or a reload of the own certificate (successful or not). A handler that throws is logged and does not affect HTTPS.

- `Problem` is why HTTPS cannot serve a certificate: `IdentityProblem` in `BuiltInCa`, the load failure of `CertificatePath` in `OwnCertificate` (it names the file, never the password), null otherwise. An app turns it into its own health finding.
- `HttpsPort` is the library's port in `BuiltInCa` and `OwnCertificate`, the port of Kestrel's `https` endpoint in `KestrelCertificate` (`0` when there is none, as with a default certificate alone, or it cannot be read), and `0` in `Off`.
- The CA values (`MdnsName`, `CaFingerprintSha256`, `NameMismatch`, `NameConflict`, `IdentityProblem`) are empty, null or false outside `BuiltInCa`; `CertificateNotAfter` and `CertificateDnsNames` are set only in `OwnCertificate` while a certificate is loaded.

**Using your own certificate (`OwnCertificate`).** Set `CertificatePath` (or `<section>:CertificatePath`); a relative path is relative to the app's content root.

- Formats: a PKCS#12 file (`.pfx`, `.p12`) with `CertificatePassword`; or a PEM file holding the server certificate first, then any intermediates, with the private key either in the same file or in `CertificateKeyPath`. An encrypted PEM key (`ENCRYPTED PRIVATE KEY`) uses `CertificatePassword`. A file that holds any PEM block, or any file when `CertificateKeyPath` is set, is read as PEM; anything else as PKCS#12, where the server certificate is the first one with a private key and the others travel as intermediates. RSA and ECDSA keys both work.
- It is served on `HttpsPort` on all interfaces, TLS 1.2 and 1.3. The intermediates in the file are sent in the handshake, so a client that trusts only the root validates the chain, on Linux. **On Windows only the server certificate is sent.** SChannel sends only a chain it can build from the machine's certificate stores, and .NET makes that possible by adding the intermediates (and, when that is not enough, the root) to the Intermediate Certification Authorities store; this library never adds anything to a certificate store, so it does not hand the intermediates to .NET there and logs a warning when the file holds any. On Windows, use a certificate issued directly by the root the clients trust, or have the clients (or the machine's store, by the operator) hold the intermediate.
- At startup one Information line gives the port, the file, the subject, the DNS names, the expiry and that the built-in CA is not used. A certificate that has expired, or expires within 30 days, is logged as a warning at load and then once a day while the app runs.
- The certificate and key files are checked every two seconds. A change (once the file has stayed the same for one more check, so a file still being copied is not read) is logged and the file is loaded again; the next handshake gets the new certificate without a restart. The previous certificate stays usable for handshakes already under way and is disposed at shutdown.
- A file that cannot be loaded (missing, unreadable, wrong password, no private key, a key that does not match) is logged as an error, sets `ITlsCaStatus.Problem`, and leaves the HTTPS listener bound with failing handshakes (Kestrel logs each at Debug). It is retried when the file changes, not before. The built-in CA is never used instead. A replaced file that cannot be loaded also takes the previous certificate out of service.
- On Windows the private key is imported into a key container in the current account's profile, as for the built-in leaf, and the container is deleted when the certificate is disposed.

**Without the built-in CA.** In `OwnCertificate`, `KestrelCertificate` and `Off` the well-known paths answer as follows (every response still carries `Cache-Control: no-store`, and none carries a file path or exception text):

| Path | Answer |
| --- | --- |
| `GET /.well-known/gameshowpro/` | 200, a short static notice (`src/GameshowPro.TlsCa/wwwroot/notice.html`): no certificate to install here. No script, buttons or downloads; same security headers as the management page. |
| `GET ca.crt`, `ca.pem`, `ca.mobileconfig` | 404 with a fixed plain-text message. |
| `GET info.json` | 200, `Access-Control-Allow-Origin: *`, with `product`, `httpsPort`, `version` and `certificateSource`; in `OwnCertificate` while a certificate is loaded also `certificateNotAfter` (Unix seconds) and `certificateDnsNames`. No CA fields. |
| `POST renew`, `POST reset` | 415 unless the body is JSON, else 409 with an `error` document. The gate is not asked. |

**When the identity cannot be used.** If the stored identity cannot be read, decrypted or verified, a first identity cannot be created or saved, or the platform cannot protect the keys or prepare the server certificate (every one of these is an `IdentityStoreException`), the app still starts. This is always on; there is no option.

- The reason is logged once as an error (by the manager), followed by one warning saying how to recover. Nothing is regenerated and the file is left as it is.
- The HTTPS listener is still bound, but every handshake fails, because there is no certificate to serve. Kestrel reports each failed handshake at Debug, not as a warning or an error per connection. Plain HTTP is unaffected, and the HTTP root redirect works as usual.
- `ITlsCaStatus.IdentityProblem` holds the reason (the exception message, which holds no key material but does name the file). While it is set, `MdnsName` and `CaFingerprintSha256` are `""` and `NameMismatch` is null; nothing throws.
- The management page is served. `info.json` answers 503 with a JSON body (`error`, `identityUnavailable: true`, `product`, `httpsPort`, `version`, `gate`) that the page uses to explain the problem and offer Reset. `ca.crt`, `ca.pem` and `ca.mobileconfig` answer 503 with a plain-text message, and `renew` answers 503 with a JSON `error`. Every 503 carries `Cache-Control: no-store` and none carries the reason.
- `POST reset` works through the gate, which is asked `ITlsCaGate.IsAllowedWithoutIdentity` because there is no identity to pass. `LoopbackGate` then accepts only `localhost` and loopback IP literals as `Host` (there is no device name yet), with the same remote-address and `Origin` checks. A successful reset answers with the new `info.json`, clears `IdentityProblem`, raises `Changed`, and the running HTTPS listener serves the new leaf to the next connection. A reset that fails in any of the ways above (it cannot save, protect the keys or prepare the server certificate) answers 500 and leaves things as they were.
- Renewal does nothing while there is no identity. The mDNS advertisement waits, and starts once a reset creates an identity.
- `TlsIdentityManager.LoadOrCreate` itself still throws for apps that use the core directly.

Other options: `StorageDirectory` (default `%ProgramData%\GameshowPro\<Product>\tls` on Windows, `/var/lib/gameshowpro/<applabel>/tls` elsewhere), `Version` (default: the entry assembly's informational version without its `+metadata` suffix), `ExplicitName` (for appliances), `Gate` (default `LoopbackGate`), `RenewWhenRemaining`, `MinimumTime`, `AdvertiseMdns` (default true; turn it off in tests) and `MdnsScopes` (default null; see "Where mDNS advertises"). Public helpers: `TlsCaPaths.WellKnownPrefix`, `TlsCaPaths.IsWellKnown(PathString)`, `LoopbackGate.IsLoopbackHost(HostString)`.

**Native AOT.** The library is marked `IsAotCompatible` and builds with no trim or AOT analyzer warnings. Its endpoints are plain `RequestDelegate` handlers and its JSON uses source-generated contexts, so it needs no minimal-API binding or reflection.

**HTTP and HTTPS together.** Kestrel binds either code-defined listeners (`Listen*`, `Kestrel:Endpoints`) or the hosting URLs (`UseUrls`, `ASPNETCORE_URLS`), and when both exist it silently ignores the URLs. Adding the HTTPS listener would therefore cancel an app's HTTP port, so the library re-applies the app's `http://` hosting URLs (and `http_ports`) as listeners next to HTTPS. The app keeps declaring its HTTP ports the way it did. If it declared none, `HttpPort` is bound on all interfaces. If it configured `Kestrel:Endpoints` (and not `preferHostingUrls`) nothing is added: Kestrel binds those endpoints itself, next to the HTTPS listener. Kestrel logs a warning, "Overriding address(es) ... Binding to endpoints defined via IConfiguration and/or UseKestrel() instead", which is harmless here: the URLs are bound as listeners. Integration tests (`KestrelIntegrationTests`) pin Kestrel's behavior and check the ports. `https://` hosting URLs are not re-applied.

The endpoints, served by `UseGameshowProTlsCa` and `MapGameshowProTlsCa` alike. Every response carries `Cache-Control: no-store`. The page and the GET endpoints are open to anyone on the LAN, over HTTP and HTTPS; no endpoint ever returns a private key.

| Method and path | Purpose |
| --- | --- |
| `GET /.well-known/gameshowpro/` | Certificate management page (one self-contained HTML file, embedded; source `src/GameshowPro.TlsCa/wwwroot/management.html`) |
| `GET /.well-known/gameshowpro/ca.crt` | CA certificate, DER (`application/x-x509-ca-cert`), for Windows and Android |
| `GET /.well-known/gameshowpro/ca.pem` | CA certificate, PEM, for Linux, macOS and scripts |
| `GET /.well-known/gameshowpro/ca.mobileconfig` | Unsigned Apple configuration profile holding the CA (`application/x-apple-aspen-config`) |
| `GET /.well-known/gameshowpro/info.json` | Name, ports, fingerprints, validity times, gate kind; `Access-Control-Allow-Origin: *` for the trust probe |
| `POST /.well-known/gameshowpro/renew` | Gated. New leaf under the same CA; clients are not affected |
| `POST /.well-known/gameshowpro/reset` | Gated. New CA and leaf; every client must trust the new CA |

`info.json` fields (the shared wire contract; times are Unix seconds): `product`, `name`, `mdnsName`, `httpsPort`, `caFingerprintSha256`, `previousCaFingerprintSha256`, `leafNotBefore`, `leafNotAfter`, `caNotAfter`, `version`, `gate` (`loopback`, `button`, or `boot` for the ESP32 firmware's five-minute window after power-up), `nameConflict`, `nameMismatch`, `certificateSource`. `certificateSource` is `ca` here (and in the 503 body while no identity is in force), `own` with an operator's certificate (`OwnCertificate` and `KestrelCertificate`), and `off` when HTTPS is off; the last two use the reduced document described under "Without the built-in CA". Readers must ignore unknown fields.

The POSTs answer 415 unless the content type is `application/json`, and 403 unless the gate allows the request; the JSON body (a time, for wire compatibility with the ESP32) is ignored, because a PC has a clock. Every other method, a CORS preflight included, gets a 405 that grants nothing. `LoopbackGate` allows a request only when the connection's remote address is loopback (IPv4-mapped IPv6 included), the `Host` is `localhost`, a loopback IP literal or `<name>.local` (not the device name while no identity is in force), and any `Origin` header names the request's own host and port. It consults only `Connection.RemoteIpAddress` and ignores `X-Forwarded-*` and `Forwarded`; an app that installs the forwarded-headers middleware changes that address itself and takes on the trust decision. Supply your own `ITlsCaGate` through `TlsCaOptions.Gate` for an administrator credential. A custom gate decides a reset without an identity in `IsAllowedWithoutIdentity`; its default implementation refuses, so a gate that does not implement it cannot recover from an unusable identity without a restart.

The page (in `BuiltInCa`; see above for the other modes) is driven only by `info.json` and absolute well-known paths, so the same file is served by the ESP32 firmware. When `info.json` answers 503 (no usable identity), it says the identity cannot be used and that Reset replaces it, and shows only Reset, explained for the gate kind in the body (a body that is not JSON, as the ESP32 firmware sends, gets the generic explanation). Otherwise it shows the name, the HTTPS link, the fingerprint, per-platform downloads with install steps, the leaf's status from the browser's clock, the CA's expiry, any name conflict or mismatch, Renew and Reset, and a trust probe: when the browser already trusts the CA, the page says so and forwards to the HTTPS address after a short countdown (not on a localhost address, where Renew and Reset must stay reachable). It is served with a restrictive `Content-Security-Policy` and cannot be framed.

## User documentation for apps

`docs/https-guide.md` is an end-user guide to the certificate page, the secure address and installing the CA, shared by every app that uses this library. An app renders it with its own values (product name, ports, builds, custom sections) and publishes the result in its own documentation. The `docs` folder ships in the NuGet package. See `docs/integrating-the-https-guide.md`.

## Building and testing

```powershell
dotnet build TlsCa.slnx -c Release
dotnet test TlsCa.slnx -c Release
dotnet pack src/GameshowPro.TlsCa/GameshowPro.TlsCa.csproj -c Release
```

**The GameshowPro.Mdns reference.** Builds use the published package by default, including on machines with a sibling Mdns checkout. `MdnsPackageVersion` is pinned to 1.1.2, the first release with `AdvertisedServiceOptions.HostName`. For coordinated development only, pass `-p:UseMdnsProject=true` to use the sibling checkout. Packing is refused with that option so a local dependency cannot accidentally enter a release.

**CI** (`.github/workflows/build.yaml`): pull requests, pushes to `main`, and manual runs validate Release tests on Windows and Ubuntu, render and build both user-guide examples, and inspect the NuGet package. The build uses the SDK pinned in `global.json`, C# 15, and warnings as errors. Successful runs on `main` publish to the GameShowPro package source, then create a version tag and GitHub release. Package restore uses the Actions variables `GSP_PACKAGE_USERNAME` and `NUGET_URL` and the secret `GSP_PACKAGE_PAT`; publishing uses the repository's `GITHUB_TOKEN` with package write permission.

The chain tests use the platform's own certificate validator (CryptoAPI on Windows, OpenSSL on Linux), so they check that the platform enforces the CA's name constraints. The handshake tests run a real `SslStream` server and client over loopback TCP. Windows-only and Linux-only tests are skipped on the other platform; the tests that check intermediates are sent, including the control in `TlsHandshakeTests`, run on Linux only, because on Windows .NET would add the intermediate to the user's certificate store. Clients trust test roots only through `X509ChainPolicy.CustomTrustStore`; no test adds anything to a certificate store. Tests work in directories under the system temporary directory and remove them, and any key containers they create, when they finish.

To inspect generated certificates with OpenSSL:

```sh
openssl x509 -in ca.pem -text -noout
openssl x509 -in leaf.pem -text -noout
openssl verify -CAfile ca.pem leaf.pem
```
