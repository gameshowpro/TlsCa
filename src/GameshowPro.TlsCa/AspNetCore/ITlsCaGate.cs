namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// The gate in front of the actions that change the identity: renewing the leaf and resetting the identity. Without
/// one, anyone on the LAN could break every client in the middle of a show.
/// </summary>
public interface ITlsCaGate
{
    /// <summary>
    /// How the gate proves presence, as carried in <c>info.json</c> and used by the management page to explain the
    /// Renew and Reset buttons: <c>loopback</c> (the request comes from the machine itself) or <c>button</c> (a button
    /// on the device was pressed recently). Any other value gets a generic explanation.
    /// </summary>
    string Kind { get; }

    /// <summary>Returns true when the request may renew the leaf or reset the identity.</summary>
    /// <param name="context">The request. The gate must not trust forwarding headers it has not been told to.</param>
    /// <param name="identity">The identity in force, whose name the request may be required to address.</param>
    ValueTask<bool> IsAllowed(HttpContext context, TlsIdentity identity);

    /// <summary>
    /// Returns true when the request may reset the identity while none is in force (the stored identity could not be
    /// loaded, or a first one could not be created). A reset is the only action offered then. Called instead of
    /// <see cref="IsAllowed"/>, because there is no identity to pass. The default refuses, so a gate written before this
    /// member existed never allows more than it did; <see cref="LoopbackGate"/> allows the machine itself.
    /// </summary>
    /// <param name="context">The request. The gate must not trust forwarding headers it has not been told to.</param>
    ValueTask<bool> IsAllowedWithoutIdentity(HttpContext context) => ValueTask.FromResult(false);
}
