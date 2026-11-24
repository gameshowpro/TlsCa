namespace GameshowPro.TlsCa;

/// <summary>
/// One network on which the ASP.NET Core integration advertises the device name over mDNS (see
/// <see cref="TlsCaOptions.MdnsScopes"/>): the interface and the local address GameshowPro.Mdns takes together in
/// <c>AdvertisedServiceOptions.NetworkInterfaceId</c> and <c>LocalAddress</c>. The advertisement publishes that address
/// only, and only on that interface.
/// </summary>
/// <param name="NetworkInterfaceId">The interface's <see cref="System.Net.NetworkInformation.NetworkInterface.Id"/>; not empty.</param>
/// <param name="LocalAddress">An IPv4 or IPv6 address of that interface.</param>
public sealed record TlsCaMdnsScope(string NetworkInterfaceId, IPAddress LocalAddress)
{
    /// <summary>The interface's <see cref="System.Net.NetworkInformation.NetworkInterface.Id"/>; never empty.</summary>
    public string NetworkInterfaceId { get; init => field = ValidInterfaceId(value, nameof(NetworkInterfaceId)); } = ValidInterfaceId(NetworkInterfaceId, nameof(NetworkInterfaceId));

    /// <summary>The address published on the interface; always IPv4 or IPv6.</summary>
    public IPAddress LocalAddress { get; init => field = ValidAddress(value, nameof(LocalAddress)); } = ValidAddress(LocalAddress, nameof(LocalAddress));

    private static string ValidInterfaceId(string value, string paramName)
    {
        ArgumentException.ThrowIfNullOrEmpty(value, paramName);
        return value;
    }

    private static IPAddress ValidAddress(IPAddress value, string paramName)
    {
        ArgumentNullException.ThrowIfNull(value, paramName);
        return value.AddressFamily is System.Net.Sockets.AddressFamily.InterNetwork or System.Net.Sockets.AddressFamily.InterNetworkV6
            ? value
            : throw new ArgumentException("LocalAddress must be an IPv4 or IPv6 address.", paramName);
    }
}
