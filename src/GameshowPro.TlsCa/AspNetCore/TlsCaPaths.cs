namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>The shared well-known paths, identical on every GameshowPro product.</summary>
public static class TlsCaPaths
{
    /// <summary>
    /// The prefix of every certificate management path, without a trailing slash. The management page is at
    /// <c>/.well-known/gameshowpro/</c>.
    /// </summary>
    public const string WellKnownPrefix = "/.well-known/gameshowpro";

    private static readonly PathString s_wellKnownPrefix = new(WellKnownPrefix);

    /// <summary>
    /// Whether <paramref name="path"/> is <see cref="WellKnownPrefix"/> or below it (whole segments, case-insensitive), so
    /// <c>/.well-known/gameshowpro-other</c> is not.
    /// </summary>
    public static bool IsWellKnown(PathString path) => path.StartsWithSegments(s_wellKnownPrefix);
}
