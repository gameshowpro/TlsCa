namespace GameshowPro.TlsCa.AspNetCore;

/// <summary>
/// Renews the leaf under the existing CA when it is close to expiry: at startup and then daily. A run while no identity is
/// in force (it could not be loaded and has not been reset yet) does nothing.
/// </summary>
internal sealed partial class TlsCaRenewalService(TlsIdentityManager manager, TimeProvider timeProvider, ILogger<TlsCaRenewalService> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RenewIfDue(stoppingToken).ConfigureAwait(false);
            using PeriodicTimer timer = new(Interval, timeProvider);
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await RenewIfDue(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private async Task RenewIfDue(CancellationToken cancellationToken)
    {
        if (!manager.IsLoaded)
        {
            // Nothing to renew; the startup failure was logged once, and a reset creates a fresh leaf.
            return;
        }

        try
        {
            _ = await manager.RenewIfDue(cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // A failed renewal must not stop the web server; the current leaf keeps being served and the next run retries.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogRenewalFailed(exception);
        }
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Renewing the TLS leaf failed; the current leaf stays in force and the renewal is retried.")]
    private partial void LogRenewalFailed(Exception exception);
}
