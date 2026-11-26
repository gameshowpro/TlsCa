namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>Applies mDNS scope changes and waits for withdrawals and the first start attempt on each new scope.</summary>
public interface ITlsCaMdns
{
    /// <summary>Snapshots <paramref name="scopes"/> when called, withdraws removed scopes, then starts new scopes.
    /// Unchanged advertisements remain running.</summary>
    /// <remarks>In built-in CA mode with mDNS enabled, call after the host starts. Start failures are returned and
    /// continue to retry in the background. If no identity exists, scopes are stored and
    /// <see cref="TlsCaMdnsApplyResult.IdentityAvailable"/> is false. In other modes, or when mDNS is disabled,
    /// only the option is stored.</remarks>
    Task<TlsCaMdnsApplyResult> ApplyScopesAsync(IReadOnlyList<TlsCaMdnsScope>? scopes, CancellationToken cancellationToken = default);

    /// <summary>Withdraws removed library advertisements, runs <paramref name="afterWithdraw"/>, then starts new ones.</summary>
    /// <remarks>The callback runs while scope reconciliation is serialized. It can stop and replace application-owned
    /// advertisements. If the callback throws or observes cancellation, removed scopes stay withdrawn and new scopes
    /// are not started. Cancellation while waiting for starts propagates, but starts already scheduled continue.
    /// With no identity, the callback still runs and scopes are stored. In modes without library advertising,
    /// the callback is not called.</remarks>
    Task<TlsCaMdnsApplyResult> ApplyScopesAsync(IReadOnlyList<TlsCaMdnsScope>? scopes, Func<CancellationToken, Task> afterWithdraw, CancellationToken cancellationToken = default);
}

/// <summary>The outcome of one awaited mDNS scope change.</summary>
/// <param name="AdvertisingEnabled">Whether the library advertises mDNS in this mode.</param>
/// <param name="IdentityAvailable">Whether a TLS identity was available for this change.</param>
/// <param name="StartedScopes">New scopes whose first advertisement start succeeded; null means unscoped.</param>
/// <param name="UnchangedScopes">Scopes whose existing advertisements were kept; null means unscoped.</param>
/// <param name="StartFailures">New scopes whose first start failed, and retained scopes whose last start failed.
/// Failed scopes continue to retry in the background.</param>
public sealed record TlsCaMdnsApplyResult(
    bool AdvertisingEnabled,
    bool IdentityAvailable,
    IReadOnlyList<TlsCaMdnsScope?> StartedScopes,
    IReadOnlyList<TlsCaMdnsScope?> UnchangedScopes,
    IReadOnlyList<TlsCaMdnsStartFailure> StartFailures);

/// <summary>A failed first advertisement start for one scope.</summary>
/// <param name="Scope">The scope, or null for the unscoped advertisement.</param>
/// <param name="Message">The exception message returned by the mDNS start attempt.</param>
/// <param name="IsNameConflict">Whether the failure reports an mDNS name conflict.</param>
public sealed record TlsCaMdnsStartFailure(TlsCaMdnsScope? Scope, string Message, bool IsNameConflict);

internal sealed class InactiveTlsCaMdns(TlsCaOptions options) : ITlsCaMdns
{
    public Task<TlsCaMdnsApplyResult> ApplyScopesAsync(IReadOnlyList<TlsCaMdnsScope>? scopes, CancellationToken cancellationToken = default) =>
        ApplyScopesCore(scopes, cancellationToken);

    public Task<TlsCaMdnsApplyResult> ApplyScopesAsync(IReadOnlyList<TlsCaMdnsScope>? scopes, Func<CancellationToken, Task> afterWithdraw, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(afterWithdraw);
        return ApplyScopesCore(scopes, cancellationToken);
    }

    private Task<TlsCaMdnsApplyResult> ApplyScopesCore(IReadOnlyList<TlsCaMdnsScope>? scopes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        options.MdnsScopes = scopes;
        return Task.FromResult(new TlsCaMdnsApplyResult(false, false, [], [], []));
    }
}
