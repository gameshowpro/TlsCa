namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// Allows a request only when someone is at the machine and the request was not steered there by another site:
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>The connection's remote address is a loopback address (IPv4-mapped IPv6 loopback included). Only
/// <see cref="ConnectionInfo.RemoteIpAddress"/> is consulted: every <c>X-Forwarded-*</c> and <c>Forwarded</c> header is
/// ignored, so a LAN client cannot claim to be local. (An app that installs the forwarded-headers middleware rewrites
/// that address itself and takes responsibility for who may forward.) A missing remote address is refused.</item>
/// <item>The <c>Host</c> header names this machine: <c>localhost</c>, a loopback IP literal, or the device's
/// <c>&lt;name&gt;.local</c> (only <c>localhost</c> and loopback literals while no identity is in force). A DNS-rebinding
/// page addressing another name is refused.</item>
/// <item>If an <c>Origin</c> header is present, its host and port equal the request's own <c>Host</c>. A page on another
/// site cannot trigger an action through the local browser.</item>
/// </list>
/// </remarks>
public sealed class LoopbackGate : ITlsCaGate
{
    /// <summary>The value of <see cref="Kind"/>.</summary>
    public const string GateKind = "loopback";

    /// <inheritdoc/>
    public string Kind => GateKind;

    /// <summary>
    /// Whether a <c>Host</c> header names this machine by one of the names a local browser uses: <c>localhost</c>
    /// (case-insensitive), <c>127.0.0.1</c> or <c>[::1]</c>, with any port. Such a browser is already in a secure context
    /// over plain HTTP, so <see cref="TlsCaApplicationBuilderExtensions.UseGameshowProTlsCa"/> does not redirect it.
    /// Narrower than what the gate accepts: other loopback literals, and the device name, are not loopback hosts here.
    /// </summary>
    public static bool IsLoopbackHost(HostString host) =>
        host.Host is { Length: > 0 } name
        && (name.Equals("localhost", StringComparison.OrdinalIgnoreCase) || name == "127.0.0.1" || name == "[::1]");

    /// <inheritdoc/>
    public ValueTask<bool> IsAllowed(HttpContext context, TlsIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(identity);
        return ValueTask.FromResult(Check(context, identity));
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The same checks as <see cref="IsAllowed"/>, except that the <c>Host</c> must be <c>localhost</c> or a loopback IP
    /// literal: with no identity there is no device name to accept.
    /// </remarks>
    public ValueTask<bool> IsAllowedWithoutIdentity(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ValueTask.FromResult(Check(context, identity: null));
    }

    private static bool Check(HttpContext context, TlsIdentity? identity)
    {
        if (context.Connection.RemoteIpAddress is not { } remote || !IsLoopback(remote))
        {
            return false;
        }

        HostString host = context.Request.Host;
        if (!host.HasValue || !IsOwnHostName(host.Host, identity))
        {
            return false;
        }

        if (context.Request.Headers.TryGetValue(HeaderNames.Origin, out StringValues origin))
        {
            return origin.Count == 1 && OriginMatchesHost(origin[0], host, context.Request.Scheme);
        }

        return true;

        static bool IsOwnHostName(string host, TlsIdentity? identity)
        {
            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                || (identity is not null && host.Equals(identity.MdnsName, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            string literal = host.StartsWith('[') && host.EndsWith(']') ? host[1..^1] : host;
            return IPAddress.TryParse(literal, out IPAddress? address) && IsLoopback(address);
        }

        // The Origin's host and port must match the request's Host; default ports follow the scheme.
        static bool OriginMatchesHost(string? origin, HostString host, string requestScheme)
        {
            // "null" (an opaque origin) and anything else that is not an absolute URL never matches.
            if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("http" or "https"))
            {
                return false;
            }

            int hostPort = host.Port ?? (requestScheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ? 443 : 80);
            return uri.Host.Equals(host.Host, StringComparison.OrdinalIgnoreCase) && uri.Port == hostPort;
        }
    }

    private static bool IsLoopback(IPAddress address) =>
        IPAddress.IsLoopback(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);

}
