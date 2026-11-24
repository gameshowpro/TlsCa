namespace GameshowPro.TlsCa;

/// <summary>
/// Builds the Apple configuration profile (<c>.mobileconfig</c>) that installs a device's CA certificate on iOS and
/// iPadOS (and macOS). The profile is unsigned and holds one <c>com.apple.security.root</c> payload: the CA in DER form.
/// </summary>
public static class AppleProfile
{
    /// <summary>The content type to serve the profile with.</summary>
    public const string ContentType = "application/x-apple-aspen-config";

    private const string IdentifierPrefix = "com.gameshowpro.tlsca.";

    /// <summary>
    /// Builds the profile for <paramref name="identity"/>. The identifiers contain the device name, so they are unique
    /// per device, and both UUIDs derive from the CA fingerprint, so the same CA always produces the same profile and a
    /// reset (a new CA) produces a new one. Installing the profile for a reset device replaces the old one.
    /// </summary>
    public static byte[] Build(TlsIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        string profileIdentifier = IdentifierPrefix + identity.Name;
        string payloadIdentifier = profileIdentifier + ".ca";
        string displayName = $"GameshowPro CA {identity.Name}";
        string description = $"Lets this device trust {identity.MdnsName}. CA fingerprint (SHA-256): {identity.CaFingerprintSha256}";

        XElement payload = Dict(
            ("PayloadCertificateFileName", Str($"{identity.Name}.crt")),
            ("PayloadContent", new XElement("data", Convert.ToBase64String(identity.CaCertificateDer.AsSpan()))),
            ("PayloadDescription", Str(description)),
            ("PayloadDisplayName", Str(displayName)),
            ("PayloadIdentifier", Str(payloadIdentifier)),
            ("PayloadType", Str("com.apple.security.root")),
            ("PayloadUUID", Str(DeriveUuid("payload", identity.CaFingerprintSha256))),
            ("PayloadVersion", new XElement("integer", 1)));
        XElement root = Dict(
            ("PayloadContent", new XElement("array", payload)),
            ("PayloadDescription", Str(description)),
            ("PayloadDisplayName", Str(displayName)),
            ("PayloadIdentifier", Str(profileIdentifier)),
            ("PayloadOrganization", Str("GameshowPro")),
            ("PayloadRemovalDisallowed", new XElement("false")),
            ("PayloadType", Str("Configuration")),
            ("PayloadUUID", Str(DeriveUuid("profile", identity.CaFingerprintSha256))),
            ("PayloadVersion", new XElement("integer", 1)));

        XDocument document = new(
            new XDeclaration("1.0", "UTF-8", null),
            new XDocumentType("plist", "-//Apple//DTD PLIST 1.0//EN", "http://www.apple.com/DTDs/PropertyList-1.0.dtd", null),
            new XElement("plist", new XAttribute("version", "1.0"), root));
        using MemoryStream stream = new();
        using (System.Xml.XmlWriter writer = System.Xml.XmlWriter.Create(stream, new() { Encoding = new UTF8Encoding(false), Indent = true }))
        {
            document.Save(writer);
        }

        return stream.ToArray();

        static XElement Str(string value) => new("string", value);
    }

    /// <summary>
    /// A version-5-style UUID from the purpose and the CA fingerprint: the first 16 bytes of the SHA-256 of both, with the
    /// version and variant bits set. Stable for a given CA.
    /// </summary>
    internal static string DeriveUuid(string purpose, string caFingerprint)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        _ = SHA256.HashData(Encoding.UTF8.GetBytes($"gameshowpro-tlsca:{purpose}:{caFingerprint}"), hash);
        Span<byte> bytes = hash[..16];
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes, bigEndian: true).ToString("D").ToUpperInvariant();
    }

    private static XElement Dict(params (string Key, XElement Value)[] entries)
    {
        XElement dict = new("dict");
        foreach ((string key, XElement value) in entries)
        {
            dict.Add(new XElement("key", key), value);
        }

        return dict;
    }
}
