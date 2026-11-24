namespace GameshowPro.TlsCa;

/// <summary>
/// Derives and validates the single DNS label that identifies one installation of an app, for example
/// <c>studio-pc-triggergate</c>. The full mDNS name is the label followed by <see cref="LocalSuffix"/>.
/// </summary>
public static class DeviceName
{
    /// <summary>The longest DNS label allowed (RFC 1035).</summary>
    public const int MaxLabelLength = 63;

    /// <summary>The host part used when the system host name has no usable characters.</summary>
    public const string FallbackHost = "gsp";

    /// <summary>The mDNS domain appended to the label to form the full name.</summary>
    public const string LocalSuffix = ".local";

    /// <summary>
    /// Derives <c>&lt;host&gt;-&lt;app&gt;</c> from the system host name and an app label.
    /// Each part is lower-cased (ASCII letters only); every character outside <c>a-z0-9-</c> becomes <c>-</c>;
    /// runs of <c>-</c> collapse; leading and trailing <c>-</c> are trimmed. An empty host part becomes
    /// <see cref="FallbackHost"/>. If the result would exceed <see cref="MaxLabelLength"/> characters the host part
    /// is truncated and the app label is kept whole.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// The app label has no usable characters, or is too long to leave room for a one-character host part.
    /// </exception>
    public static string Derive(string hostName, string appLabel)
    {
        ArgumentNullException.ThrowIfNull(hostName);
        ArgumentNullException.ThrowIfNull(appLabel);

        string app = Sanitize(appLabel);
        if (app.Length == 0)
        {
            throw new ArgumentException("The app label must contain at least one character in a-z, 0-9 or -, other than hyphens.", nameof(appLabel));
        }

        // The host part needs at least one character and the joining hyphen.
        int maxHostLength = MaxLabelLength - 1 - app.Length;
        if (maxHostLength < 1)
        {
            throw new ArgumentException($"The sanitized app label must be at most {MaxLabelLength - 2} characters.", nameof(appLabel));
        }

        string host = Sanitize(hostName);
        if (host.Length == 0)
        {
            host = FallbackHost;
        }

        if (host.Length > maxHostLength)
        {
            // A sanitized part starts with a letter or digit, so trimming after truncation never empties it.
            host = host[..maxHostLength].TrimEnd('-');
        }

        return $"{host}-{app}";

        static string Sanitize(string part)
        {
            StringBuilder result = new(part.Length);
            foreach (char raw in part)
            {
                char c = raw is >= 'A' and <= 'Z' ? (char)(raw + ('a' - 'A')) : raw;
                if (!IsLabelCharacter(c))
                {
                    c = '-';
                }

                if (c == '-' && (result.Length == 0 || result[^1] == '-'))
                {
                    // Drops leading hyphens and collapses runs.
                    continue;
                }

                _ = result.Append(c);
            }

            if (result.Length > 0 && result[^1] == '-')
            {
                result.Length--;
            }

            return result.ToString();
        }
    }

    /// <summary>
    /// True when <paramref name="label"/> is a valid device name: 1 to 63 characters from <c>a-z</c>, <c>0-9</c> and
    /// <c>-</c>, not starting or ending with <c>-</c>.
    /// </summary>
    public static bool IsValidLabel(string? label)
    {
        if (string.IsNullOrEmpty(label) || label.Length > MaxLabelLength || label[0] == '-' || label[^1] == '-')
        {
            return false;
        }

        foreach (char c in label)
        {
            if (!IsLabelCharacter(c))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Returns the full mDNS name, <c>&lt;label&gt;.local</c>, for a valid device name.</summary>
    /// <exception cref="ArgumentException"><paramref name="label"/> is not a valid device name.</exception>
    public static string ToMdnsName(string label)
    {
        ThrowIfInvalid(label);
        return label + LocalSuffix;
    }

    internal static void ThrowIfInvalid(string label, [CallerArgumentExpression(nameof(label))] string? paramName = null)
    {
        ArgumentNullException.ThrowIfNull(label, paramName);
        if (!IsValidLabel(label))
        {
            throw new ArgumentException("The device name must be 1 to 63 characters from a-z, 0-9 and -, and must not start or end with -.", paramName);
        }
    }

    private static bool IsLabelCharacter(char c) => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-';
}
