using System.Diagnostics;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

/// <summary>Waits for a background cycle the fake clock has released to finish: the clock moves at once, the work does not.</summary>
internal static class Eventually
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(5);

    public static async Task<bool> IsTrueAsync(Func<bool> condition)
    {
        var started = Stopwatch.GetTimestamp();

        while (!condition())
        {
            if (Stopwatch.GetElapsedTime(started) > Patience)
                return false;

            await Task.Delay(10);
        }

        return true;
    }
}
