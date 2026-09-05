namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Runs one piece of work on an interval and stops it on demand.</summary>
/// <remarks>
/// The interval is counted after the work finishes rather than between starts, so a run slower than the
/// interval can neither overlap the next one nor queue them up. The work is expected to answer for its
/// own failures: an exception out of it ends the loop.
/// </remarks>
internal sealed class PeriodicRefresh(TimeSpan interval, Func<CancellationToken, Task> work) : IDisposable
{
    /// <summary>How long <see cref="Dispose"/> waits for the work in flight before abandoning it.</summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);

    private CancellationTokenSource? _stopping;
    private Task? _running;

    /// <summary>Starts the loop; a second call does nothing.</summary>
    public void Start()
    {
        if (_running is not null)
            return;

        _stopping = new CancellationTokenSource();
        _running = RunAsync(_stopping.Token);
    }

    /// <summary>Stops the loop and waits for the work in flight.</summary>
    /// <remarks>
    /// The token source is left undisposed when the wait runs out: a loop still using its token would
    /// otherwise fault on an object that has gone, and leaking one source beats that.
    /// </remarks>
    public void Dispose()
    {
        _stopping?.Cancel();

        if (_running?.Wait(DrainTimeout) is not false)
            _stopping?.Dispose();
    }

    private async Task RunAsync(CancellationToken stopping)
    {
        while (!stopping.IsCancellationRequested)
        {
            if (!await IdleAsync(stopping).ConfigureAwait(false))
                return;

            await work(stopping).ConfigureAwait(false);
        }
    }

    private async Task<bool> IdleAsync(CancellationToken stopping)
    {
        try
        {
            await Task.Delay(interval, stopping).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
