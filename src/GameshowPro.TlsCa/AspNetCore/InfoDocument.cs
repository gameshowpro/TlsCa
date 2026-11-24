namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>The values of the <c>certificateSource</c> field of <c>info.json</c>.</summary>
internal static class CertificateSources
{
    /// <summary>The per-installation CA (<see cref="TlsCaMode.BuiltInCa"/>).</summary>
    public const string Ca = "ca";

    /// <summary>A certificate the operator provides (<see cref="TlsCaMode.OwnCertificate"/> and <see cref="TlsCaMode.KestrelCertificate"/>).</summary>
    public const string Own = "own";

    /// <summary>HTTPS is off (<see cref="TlsCaMode.Off"/>).</summary>
    public const string Off = "off";

    public static string For(TlsCaMode mode) => mode switch
    {
        TlsCaMode.BuiltInCa => Ca,
        TlsCaMode.Off => Off,
        TlsCaMode.OwnCertificate or TlsCaMode.KestrelCertificate => Own,
        _ => Own,
    };
}

/// <summary>
/// The body of <c>info.json</c>, the shared wire contract for every GameshowPro product. Times are Unix seconds,
/// fingerprints are upper-case hex pairs separated by <c>:</c>. Readers must ignore unknown fields.
/// </summary>
internal sealed record InfoDocument(
    [property: JsonPropertyName("product")] string Product,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("mdnsName")] string MdnsName,
    [property: JsonPropertyName("httpsPort")] int HttpsPort,
    [property: JsonPropertyName("caFingerprintSha256")] string CaFingerprintSha256,
    [property: JsonPropertyName("previousCaFingerprintSha256")] string? PreviousCaFingerprintSha256,
    [property: JsonPropertyName("leafNotBefore")] long LeafNotBefore,
    [property: JsonPropertyName("leafNotAfter")] long LeafNotAfter,
    [property: JsonPropertyName("caNotAfter")] long CaNotAfter,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("gate")] string Gate,
    [property: JsonPropertyName("nameConflict")] bool NameConflict,
    [property: JsonPropertyName("nameMismatch")] string? NameMismatch,
    [property: JsonPropertyName("certificateSource")] string CertificateSource,
    [property: JsonPropertyName("secureAddress")] string? SecureAddress,
    [property: JsonPropertyName("setupAddress")] string? SetupAddress,
    [property: JsonPropertyName("fallbackAddress")] string? FallbackAddress,
    [property: JsonPropertyName("fallbackAddresses")] string[] FallbackAddresses,
    [property: JsonPropertyName("allowHttpFallback")] bool AllowHttpFallback,
    [property: JsonPropertyName("allowHttpsFallback")] bool AllowHttpsFallback)
{
    /// <summary>The document for <paramref name="identity"/>, a snapshot of the identity in force.</summary>
    public static InfoDocument Create(TlsIdentity identity, TlsIdentityManager manager, TlsCaOptions options, ITlsCaGate gate, TlsCaStatus status, string[] fallbackAddresses) =>
        new(
            options.Product,
            identity.Name,
            identity.MdnsName,
            options.HttpsPort,
            identity.CaFingerprintSha256,
            identity.PreviousCaFingerprintSha256,
            identity.LeafNotBefore.ToUnixTimeSeconds(),
            identity.LeafNotAfter.ToUnixTimeSeconds(),
            identity.CaNotAfter.ToUnixTimeSeconds(),
            options.Version,
            gate.Kind,
            status.NameConflict,
            manager.NameMismatchFor(identity),
            CertificateSources.Ca,
            $"https://{identity.MdnsName}:{options.HttpsPort}/",
            options.HttpPort > 0 ? AddressSuggestions.BuildSetupAddress(identity.MdnsName, options.HttpPort) : null,
            fallbackAddresses.Length == 1 ? fallbackAddresses[0] : null,
            fallbackAddresses,
            options.AllowHttpFallback,
            options.AllowHttpsFallback);
}

/// <summary>
/// The body of <c>info.json</c> outside <see cref="TlsCaMode.BuiltInCa"/>: no CA fields. <c>certificateNotAfter</c>
/// (Unix seconds) and <c>certificateDnsNames</c> are present only in <see cref="TlsCaMode.OwnCertificate"/> while a
/// certificate is loaded. <c>httpsPort</c> is <see cref="ITlsCaStatus.HttpsPort"/>. Readers must ignore unknown fields.
/// </summary>
internal sealed record CertificateInfoDocument(
    [property: JsonPropertyName("product")] string Product,
    [property: JsonPropertyName("httpsPort")] int HttpsPort,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("certificateSource")] string CertificateSource,
    [property: JsonPropertyName("certificateNotAfter"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? CertificateNotAfter,
    [property: JsonPropertyName("certificateDnsNames"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string[]? CertificateDnsNames,
    [property: JsonPropertyName("secureAddress")] string? SecureAddress,
    [property: JsonPropertyName("setupAddress")] string? SetupAddress,
    [property: JsonPropertyName("fallbackAddress")] string? FallbackAddress,
    [property: JsonPropertyName("fallbackAddresses")] string[] FallbackAddresses,
    [property: JsonPropertyName("allowHttpFallback")] bool AllowHttpFallback,
    [property: JsonPropertyName("allowHttpsFallback")] bool AllowHttpsFallback);

/// <summary>The body of a failed renew or reset: a fixed message, never exception text.</summary>
internal sealed record ErrorDocument([property: JsonPropertyName("error")] string Error);

/// <summary>
/// The body of the 403 that a gated renew or reset answers: a fixed message and a <c>reason</c> code the management page
/// uses to choose its wording. The library has one refusal point (the pluggable <see cref="ITlsCaGate"/> says only yes or
/// no), so the code is always <c>refused</c>; the ESP32 firmware, which checks the Host, the Origin and its boot window
/// itself, answers <c>host</c>, <c>origin</c> or <c>gate-closed</c> in the same shape.
/// </summary>
internal sealed record RefusalDocument(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("reason")] string Reason);

/// <summary>
/// The body of the 503 that <c>info.json</c> answers while no identity is in force: a fixed message (never the reason,
/// which names local paths; that is in the log and <see cref="ITlsCaStatus.IdentityProblem"/>), plus what the management
/// page needs to offer a reset. <c>identityUnavailable</c> is always true. Readers must ignore unknown fields.
/// </summary>
internal sealed record UnavailableDocument(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("identityUnavailable")] bool IdentityUnavailable,
    [property: JsonPropertyName("product")] string Product,
    [property: JsonPropertyName("httpsPort")] int HttpsPort,
    [property: JsonPropertyName("version")] string? Version,
    [property: JsonPropertyName("gate")] string Gate,
    [property: JsonPropertyName("certificateSource")] string CertificateSource,
    [property: JsonPropertyName("secureAddress")] string? SecureAddress,
    [property: JsonPropertyName("setupAddress")] string? SetupAddress,
    [property: JsonPropertyName("fallbackAddress")] string? FallbackAddress,
    [property: JsonPropertyName("fallbackAddresses")] string[] FallbackAddresses,
    [property: JsonPropertyName("allowHttpFallback")] bool AllowHttpFallback,
    [property: JsonPropertyName("allowHttpsFallback")] bool AllowHttpsFallback);

/// <summary>Source-generated serialization, so the field names cannot drift and nothing is found by reflection.</summary>
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.Never, WriteIndented = false)]
[JsonSerializable(typeof(InfoDocument))]
[JsonSerializable(typeof(CertificateInfoDocument))]
[JsonSerializable(typeof(ErrorDocument))]
[JsonSerializable(typeof(RefusalDocument))]
[JsonSerializable(typeof(UnavailableDocument))]
internal sealed partial class TlsCaJsonContext : JsonSerializerContext;
