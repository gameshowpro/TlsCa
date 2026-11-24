namespace GameshowPro.TlsCa;

/// <summary>What happened to the identity in a <see cref="TlsIdentityManager.Changed"/> event.</summary>
public enum TlsIdentityChange
{
    /// <summary>An existing identity was loaded from the store.</summary>
    Loaded,

    /// <summary>No identity was stored, so a new one was created (first run).</summary>
    Created,

    /// <summary>A new leaf was issued under the same CA. Clients are not affected.</summary>
    Renewed,

    /// <summary>A new CA and leaf replaced the identity. Every client must install the new CA certificate.</summary>
    Reset,
}

/// <summary>Carries the identity now in force and what changed.</summary>
public sealed class TlsIdentityChangedEventArgs(TlsIdentity identity, TlsIdentityChange change) : EventArgs
{
    /// <summary>The identity now in force.</summary>
    public TlsIdentity Identity { get; } = identity;

    /// <summary>What happened.</summary>
    public TlsIdentityChange Change { get; } = change;
}
