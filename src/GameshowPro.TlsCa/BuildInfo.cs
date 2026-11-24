namespace GameshowPro.TlsCa;

/// <summary>Facts stamped into this assembly at build time (see the project file).</summary>
internal static class BuildInfo
{
    private const string BuildTimestampKey = "GameshowPro.TlsCa.BuildTimestamp";

    /// <summary>The UTC time this assembly was built, to the second.</summary>
    public static DateTimeOffset Timestamp { get; } = ReadTimestamp();

    private static DateTimeOffset ReadTimestamp()
    {
        string? value = typeof(BuildInfo).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => attribute.Key == BuildTimestampKey)?.Value;
        // The project file always stamps the value; the fallback only keeps a hand-built assembly usable, with no floor
        // beyond the Unix epoch.
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset timestamp)
            ? timestamp
            : DateTimeOffset.UnixEpoch;
    }
}
