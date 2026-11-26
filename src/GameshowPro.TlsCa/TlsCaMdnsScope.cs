namespace GameshowPro.TlsCa;

/// <summary>One adapter and the complete set of its addresses to advertise over mDNS.</summary>
public sealed record TlsCaMdnsScope
{
    private string _networkInterfaceId;
    private ImmutableArray<IPAddress> _addresses;

    /// <summary>Creates a scope containing one address. The original constructor remains supported.</summary>
    public TlsCaMdnsScope(string NetworkInterfaceId, IPAddress LocalAddress)
        : this(NetworkInterfaceId, (IReadOnlyCollection<IPAddress>)[LocalAddress])
    {
    }

    /// <summary>Creates a scope containing every selected address on one adapter.</summary>
    public TlsCaMdnsScope(string NetworkInterfaceId, IReadOnlyCollection<IPAddress> LocalAddresses)
    {
        _networkInterfaceId = ValidInterfaceId(NetworkInterfaceId);
        _addresses = Snapshot(LocalAddresses);
    }

    /// <summary>The interface's <see cref="System.Net.NetworkInformation.NetworkInterface.Id"/>.</summary>
    public string NetworkInterfaceId
    {
        get => _networkInterfaceId;
        init => _networkInterfaceId = ValidInterfaceId(value);
    }

    /// <summary>The first address, for compatibility with the original single-address API.</summary>
    public IPAddress LocalAddress
    {
        get => CopyAddress(_addresses[0]);
        init => _addresses = Snapshot([value]);
    }

    /// <summary>The immutable, nonempty set of IPv4 and IPv6 addresses published on this adapter.</summary>
    public IReadOnlyCollection<IPAddress> LocalAddresses
    {
        get => [.. _addresses.Select(CopyAddress)];
        init => _addresses = Snapshot(value);
    }

    /// <summary>Preserves the original two-value positional record deconstruction.</summary>
    public void Deconstruct(out string NetworkInterfaceId, out IPAddress LocalAddress)
    {
        NetworkInterfaceId = this.NetworkInterfaceId;
        LocalAddress = this.LocalAddress;
    }

    /// <summary>Scopes compare by adapter and address set, independent of address order and duplicates.</summary>
    public bool Equals(TlsCaMdnsScope? other) => other is not null
        && StringComparer.Ordinal.Equals(NetworkInterfaceId, other.NetworkInterfaceId)
        && _addresses.ToHashSet().SetEquals(other._addresses);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        int hash = StringComparer.Ordinal.GetHashCode(NetworkInterfaceId);
        foreach (IPAddress address in _addresses.Distinct().OrderBy(static address => address.ToString(), StringComparer.Ordinal))
        {
            hash = HashCode.Combine(hash, address);
        }

        return hash;
    }

    private static string ValidInterfaceId(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        return value;
    }

    private static ImmutableArray<IPAddress> Snapshot(IReadOnlyCollection<IPAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        if (addresses.Count == 0)
        {
            throw new ArgumentException("LocalAddresses cannot be empty.", nameof(addresses));
        }

        ImmutableArray<IPAddress>.Builder result = ImmutableArray.CreateBuilder<IPAddress>(addresses.Count);
        foreach (IPAddress address in addresses)
        {
            ArgumentNullException.ThrowIfNull(address);
            if (address.AddressFamily is not (System.Net.Sockets.AddressFamily.InterNetwork or System.Net.Sockets.AddressFamily.InterNetworkV6))
            {
                throw new ArgumentException("LocalAddresses must contain only IPv4 or IPv6 addresses.", nameof(addresses));
            }

            result.Add(CopyAddress(address));
        }

        return [.. result.Distinct()];
    }

    private static IPAddress CopyAddress(IPAddress address) => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
        ? new IPAddress(address.GetAddressBytes(), address.ScopeId)
        : new IPAddress(address.GetAddressBytes());
}
