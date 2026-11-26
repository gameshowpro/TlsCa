namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>Builds informational browser addresses without probing or connecting to the network.</summary>
internal static class AddressSuggestions
{
    private static readonly ImmutableArray<string> s_virtualMarkers =
        ["zerotier", "tailscale", "wireguard", "wintun", "openvpn", "tap-windows", "vpn", "virtual", "vmware", "vbox", "hyper-v", "vethernet", "docker", "podman"];

    /// <summary>The built-in CA's HTTP management page, independent of the optional HTTP-root redirect.</summary>
    internal static string BuildSetupAddress(string mdnsName, int httpPort) =>
        $"http://{mdnsName}:{httpPort}{TlsCaPaths.WellKnownPrefix}/";

    /// <summary>
    /// Explicit mDNS scopes are authoritative, including VPN scopes chosen by the app. Otherwise a usable request-local
    /// address is authoritative; loopback requests list eligible physical LAN IPv4 addresses with a default gateway.
    /// </summary>
    internal static string[] FallbackAddresses(
        IPAddress? localAddress,
        IReadOnlyList<TlsCaMdnsScope>? scopes,
        IEnumerable<NetworkSnapshot> networks,
        int port,
        bool https = false)
    {
        if (port <= 0)
        {
            return [];
        }

        IEnumerable<IPAddress> addresses;
        if (scopes is not null)
        {
            addresses = scopes.SelectMany(static scope => scope.LocalAddresses);
        }
        else if (Normalize(localAddress) is { } local && IsUsable(local))
        {
            addresses = [local];
        }
        else
        {
            addresses = networks
                .Where(IsEligibleNetwork)
                .SelectMany(static network => network.Addresses)
                .Where(IsPrivateLanIpv4);
        }

        return [.. addresses
            .Select(Normalize)
            .Where(static address => address is not null)
            .Select(static address => address!)
            .Where(IsUsable)
            .Distinct()
            .OrderBy(static address => address.AddressFamily)
            .ThenBy(static address => Convert.ToHexString(address.GetAddressBytes()), StringComparer.Ordinal)
            .Select(address => Format(address, port, https))];

        static bool IsEligibleNetwork(NetworkSnapshot network) => network.IsUp
            && network.HasDefaultGateway
            && network.Type is (NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211
                or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.FastEthernetT)
            && !LooksVirtual(network.Name)
            && !LooksVirtual(network.Description);

        // .NET has no reliable physical-adapter flag. Be conservative for automatic discovery; an explicit scope wins.
        static bool LooksVirtual(string value)
        {
            return s_virtualMarkers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
        }

        static string Format(IPAddress address, int port, bool https)
        {
            string host = address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
            return $"{(https ? "https" : "http")}://{host}:{port}/";
        }

        static IPAddress? Normalize(IPAddress? address) => address?.IsIPv4MappedToIPv6 == true ? address.MapToIPv4() : address;

        static bool IsUsable(IPAddress address)
        {
            if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6Multicast
                || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast))
            {
                return false;
            }

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = address.GetAddressBytes();
                return bytes[0] is > 0 and < 224 && !(bytes[0] == 169 && bytes[1] == 254);
            }

            return address.AddressFamily == AddressFamily.InterNetworkV6;
        }

        static bool IsPrivateLanIpv4(IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork || !IsUsable(address))
            {
                return false;
            }

            byte[] bytes = address.GetAddressBytes();
            return bytes[0] == 10
                || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
                || bytes[0] == 192 && bytes[1] == 168;
        }
    }

    /// <summary>Read-only network facts for deterministic selection tests.</summary>
    internal sealed record NetworkSnapshot(
        string Name,
        string Description,
        NetworkInterfaceType Type,
        bool IsUp,
        bool HasDefaultGateway,
        ImmutableArray<IPAddress> Addresses);

    /// <summary>Snapshots of local interfaces; enumeration makes no network connection.</summary>
    internal static IEnumerable<NetworkSnapshot> OperationalNetworks()
    {
        try
        {
            return [.. NetworkInterface.GetAllNetworkInterfaces().Select(Snapshot)];

            static NetworkSnapshot Snapshot(NetworkInterface network)
            {
                IPInterfaceProperties properties = network.GetIPProperties();
                bool hasGateway = properties.GatewayAddresses.Any(static gateway =>
                    gateway.Address.AddressFamily == AddressFamily.InterNetwork
                    && !gateway.Address.Equals(IPAddress.Any));
                ImmutableArray<IPAddress> addresses = [.. properties.UnicastAddresses.Select(static unicast => unicast.Address)];
                return new NetworkSnapshot(network.Name, network.Description, network.NetworkInterfaceType,
                    network.OperationalStatus == OperationalStatus.Up, hasGateway, addresses);
            }
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }
}
