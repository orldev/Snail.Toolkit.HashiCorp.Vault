using System.Diagnostics.CodeAnalysis;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Runs one piece of work on an interval and stops it on demand.</summary>
/// <remarks>
/// The interval is counted after the work finishes rather than between starts, so a run slower than the
/// interval can neither overlap the next one nor queue them up. The work is expected to answer for its
/// own failures: an exception out of it ends the loop. The interval is measured on the clock given, so a
/// test moves it by hand instead of sleeping through it.
/// </remarks>
internal sealed class PeriodicRefresh(TimeSpan interval, Func<CancellationToken, Task> work, TimeProvider time) : IDisposable
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
    /// otherwise fault on an object that has gone, and leaking one source beats that. A loop that ended in
    /// a failure has nothing left to drain, and Dispose is not where that failure is reported.
    /// </remarks>
    public void Dispose()
    {
        _stopping?.Cancel();

        if (_running is null || HasDrained(_running))
            _stopping?.Dispose();
    }

    /// <summary>Waits the drain out, and takes a loop that already failed as drained.</summary>
    [SuppressMessage("Usage", "VSTHRD002:Avoid problematic synchronous waits", Justification = "Dispose is synchronous by contract and the wait is bounded by DrainTimeout.")]
    private static bool HasDrained(Task running)
    {
        try
        {
            return running.Wait(DrainTimeout);
        }
        catch (AggregateException)
        {
            return true;
        }
    }

    private async Task RunAsync(CancellationToken stopping)
    {
        while (!stopping.IsCancellationRequested)
        {
            if (!await TryWaitAsync(stopping).ConfigureAwait(false))
                return;

            await work(stopping).ConfigureAwait(false);
        }
    }

    private async Task<bool> TryWaitAsync(CancellationToken stopping)
    {
        try
        {
            await Task.Delay(interval, time, stopping).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
