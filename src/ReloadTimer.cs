using Microsoft.Extensions.Primitives;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Produces change tokens that fire on a fixed interval.</summary>
internal sealed class ReloadTimer(TimeSpan interval) : IDisposable
{
    private CancellationTokenSource? _cancellation;

    public IChangeToken Watch()
    {
        _cancellation?.Dispose();
        _cancellation = new CancellationTokenSource(interval);
        return new CancellationChangeToken(_cancellation.Token);
    }

    public void Dispose() => _cancellation?.Dispose();
}
