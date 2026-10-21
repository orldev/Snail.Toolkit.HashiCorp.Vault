using Microsoft.Extensions.Time.Testing;

namespace Snail.Toolkit.HashiCorp.Vault.Tests.Chaos;

/// <summary>The diagnostics sink the host supplies is the one failure the provider cannot report through the sink.</summary>
public class LoggerSinkTests
{
    private static VaultOptions Options(params VaultSecret[] secrets) => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        ReloadCheckIntervalSeconds = 1,
        Logger = (_, exception) =>
        {
            if (exception is not null)
                throw new InvalidOperationException("the sink is broken");
        },
        Secrets = secrets,
    };

    /// <summary>
    /// A sink that throws when handed a failure must not take the reload loop with it, nor surface as the
    /// loop's faulted task where Dispose waits for it.
    /// </summary>
    [Fact]
    public async Task Dispose_LoggerThatThrowsOnFailures_DisposesQuietly()
    {
        var reader = new FakeVaultReader().Set("mongo", 1, """{"Connection": "a"}""");
        var time = new FakeTimeProvider();
        var provider = new VaultConfigurationProvider(Options(new VaultSecret(Path: "mongo")), reader, time);
        provider.Load();
        reader.VersionFailure = new HttpRequestException("permission denied");
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(await Eventually.IsTrueAsync(() => reader.Attempts >= 3));

        Assert.Null(Record.Exception(provider.Dispose));
    }

    /// <summary>
    /// The same broken sink, seen from the application: the rotation after the one failure it reported is
    /// still picked up, because the loop outlives the sink's own exception.
    /// </summary>
    [Fact]
    public async Task Refresh_LoggerThatThrowsOnFailures_KeepsReloading()
    {
        var reader = new FakeVaultReader().Set("mongo", 1, """{"Connection": "a"}""");
        var time = new FakeTimeProvider();
        using var provider = new VaultConfigurationProvider(Options(new VaultSecret(Path: "mongo")), reader, time);
        provider.Load();
        reader.VersionFailure = new HttpRequestException("permission denied");
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.True(await Eventually.IsTrueAsync(() => reader.Attempts >= 3));

        reader.VersionFailure = null;
        reader.Set("mongo", 2, """{"Connection": "b"}""");
        time.Advance(TimeSpan.FromSeconds(1));

        Assert.True(await Eventually.IsTrueAsync(
            () => provider.TryGet("mongo:Connection", out var value) && value == "b"));
    }
}
