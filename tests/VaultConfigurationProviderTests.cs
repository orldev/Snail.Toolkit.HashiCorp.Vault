global using Xunit;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

/// <summary>Loading, retrying, reloading and shutdown — the behaviour the provider itself owns.</summary>
public class VaultConfigurationProviderTests
{
    private static VaultOptions Options(params VaultSecret[] secrets) => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        Logger = (_, _) => { },
        Secrets = secrets,
    };

    private static VaultConfigurationProvider Loaded(VaultOptions options, FakeVaultReader reader)
    {
        var provider = new VaultConfigurationProvider(options, reader);
        provider.Load();
        return provider;
    }

    [Fact]
    public void Load_MapsSecretUnderItsPathByDefault()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "mongodb://localhost:27017", "Database": "keynex"}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "mongo")), reader);

        Assert.True(provider.TryGet("mongo:Connection", out var connection));
        Assert.Equal("mongodb://localhost:27017", connection);
        Assert.True(provider.TryGet("mongo:Database", out var database));
        Assert.Equal("keynex", database);
    }

    [Fact]
    public void Load_ConfigurationPrefixOverridesThePath()
    {
        var reader = new FakeVaultReader()
            .Set("keynex/assets", 1, """{"SecretKey": "cipher-key"}""");

        using var provider = Loaded(
            Options(new VaultSecret(Path: "keynex/assets", ConfigurationPrefix: "Assets")), reader);

        Assert.True(provider.TryGet("Assets:SecretKey", out var value));
        Assert.Equal("cipher-key", value);
    }

    [Fact]
    public void Load_EmptyPrefixMapsKeysToTheRoot()
    {
        var reader = new FakeVaultReader()
            .Set("shared", 1, """{"Seq": "http://seq:5341"}""");

        using var provider = Loaded(
            Options(new VaultSecret(Path: "shared", ConfigurationPrefix: "")), reader);

        Assert.True(provider.TryGet("Seq", out var value));
        Assert.Equal("http://seq:5341", value);
    }

    [Fact]
    public void Load_KeysFilterIsCaseInsensitive()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a", "Database": "b"}""");

        using var provider = Loaded(
            Options(new VaultSecret(Path: "mongo", Keys: ["connection"])), reader);

        Assert.True(provider.TryGet("mongo:Connection", out _));
        Assert.False(provider.TryGet("mongo:Database", out _));
    }

    [Fact]
    public void Load_NestedJsonAndScalarArraysBecomeSections()
    {
        var reader = new FakeVaultReader()
            .Set("app", 1, """{"Nested": {"Inner": {"Value": "x"}, "Hosts": ["a", "b"]}}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "app")), reader);

        Assert.True(provider.TryGet("app:Nested:Inner:Value", out var inner));
        Assert.Equal("x", inner);
        Assert.True(provider.TryGet("app:Nested:Hosts:0", out var first));
        Assert.Equal("a", first);
        Assert.True(provider.TryGet("app:Nested:Hosts:1", out var second));
        Assert.Equal("b", second);
    }

    [Fact]
    public void Load_StringValueCarryingJsonIsUnwrapped()
    {
        var reader = new FakeVaultReader()
            .Set("app", 1, """{"Serilog": "{\"MinimumLevel\": \"Debug\"}"}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "app")), reader);

        Assert.True(provider.TryGet("app:Serilog:MinimumLevel", out var level));
        Assert.Equal("Debug", level);
    }

    [Fact]
    public void Load_StringValueCarryingJsonStaysTextWhenExpandingIsOff()
    {
        var reader = new FakeVaultReader()
            .Set("app", 1, """{"Serilog": "{\"MinimumLevel\": \"Debug\"}"}""");
        var options = Options(new VaultSecret(Path: "app"));
        options.ExpandJsonValues = false;

        using var provider = Loaded(options, reader);

        Assert.False(provider.TryGet("app:Serilog:MinimumLevel", out _));
        Assert.True(provider.TryGet("app:Serilog", out var raw));
        Assert.Equal("""{"MinimumLevel": "Debug"}""", raw);
    }

    [Fact]
    public void Load_OptionalSourceSwallowsTheFailure()
    {
        var reader = new FakeVaultReader { Failure = new HttpRequestException("vault is down") };
        var options = Options(new VaultSecret(Path: "mongo"));
        options.Optional = true;
        options.LoadTimeoutSeconds = 1;
        options.ReconnectIntervalSeconds = 1;

        using var provider = new VaultConfigurationProvider(options, reader);
        provider.Load();

        Assert.False(provider.TryGet("mongo:Connection", out _));
    }

    [Fact]
    public void Load_RequiredSourceFailsWithTimeout()
    {
        var reader = new FakeVaultReader { Failure = new HttpRequestException("vault is down") };
        var options = Options(new VaultSecret(Path: "mongo"));
        options.LoadTimeoutSeconds = 1;
        options.ReconnectIntervalSeconds = 1;

        using var provider = new VaultConfigurationProvider(options, reader);

        Assert.Throws<TimeoutException>(provider.Load);
    }

    [Fact]
    public void Load_MissingSecretIsAConfigurationError()
    {
        var reader = new FakeVaultReader { Failure = new SecretNotFoundException("mongo") };
        var options = Options(new VaultSecret(Path: "mongo"));

        using var provider = new VaultConfigurationProvider(options, reader);

        Assert.Throws<SecretNotFoundException>(provider.Load);
    }

    [Fact]
    public void Load_OptionalSourceStillFailsOnAMissingSecret()
    {
        var reader = new FakeVaultReader { Failure = new SecretNotFoundException("mongo") };
        var options = Options(new VaultSecret(Path: "mongo"));
        options.Optional = true;

        using var provider = new VaultConfigurationProvider(options, reader);

        Assert.Throws<SecretNotFoundException>(provider.Load);
    }

    [Fact]
    public async Task Reload_SkipsTheReadWhenTheVersionHasNotMoved()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a"}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "mongo")), reader);
        await provider.ReloadAsync(CancellationToken.None);

        Assert.Equal(1, reader.SecretReads);
        Assert.Equal(1, reader.VersionReads);
    }

    [Fact]
    public async Task Reload_KnownVersionsFollowTheSecretNotItsPositionInTheArray()
    {
        var reader = new FakeVaultReader()
            .Set("first", 1, """{"A": "1"}""")
            .Set("second", 5, """{"B": "2"}""");
        var options = Options(new VaultSecret(Path: "first"), new VaultSecret(Path: "second"));

        using var provider = Loaded(options, reader);
        options.Secrets = [options.Secrets![1], options.Secrets[0]];
        await provider.ReloadAsync(CancellationToken.None);

        Assert.Equal(2, reader.SecretReads);
    }

    [Fact]
    public async Task Reload_RefusedVersionProbeFallsBackToTheFullRead()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a"}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "mongo")), reader);
        reader.VersionFailure = new HttpRequestException("permission denied");
        reader.Set("mongo", 2, """{"Connection": "b"}""");
        await provider.ReloadAsync(CancellationToken.None);

        Assert.True(provider.TryGet("mongo:Connection", out var value));
        Assert.Equal("b", value);
    }

    [Fact]
    public async Task Reload_UnknownVersionRereadsTheSecretInsteadOfSkippingIt()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", null, """{"Connection": "a"}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "mongo")), reader);
        await provider.ReloadAsync(CancellationToken.None);

        Assert.Equal(2, reader.SecretReads);
    }

    [Fact]
    public async Task Reload_PicksUpANewVersionAndRaisesTheToken()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a"}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "mongo")), reader);
        var reloaded = false;
        provider.GetReloadToken().RegisterChangeCallback(_ => reloaded = true, null);

        reader.Set("mongo", 2, """{"Connection": "b"}""");
        await provider.ReloadAsync(CancellationToken.None);

        Assert.True(provider.TryGet("mongo:Connection", out var value));
        Assert.Equal("b", value);
        Assert.True(reloaded);
    }

    [Fact]
    public async Task Reload_SameContentDoesNotRaiseTheToken()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a"}""");

        using var provider = Loaded(Options(new VaultSecret(Path: "mongo")), reader);
        var reloaded = false;
        provider.GetReloadToken().RegisterChangeCallback(_ => reloaded = true, null);

        reader.Set("mongo", 2, """{"Connection": "a"}""");
        await provider.ReloadAsync(CancellationToken.None);

        Assert.False(reloaded);
    }

    [Fact]
    public async Task Reload_AfterAnOptionalStartWithoutVaultRaisesTheToken()
    {
        var reader = new FakeVaultReader { Failure = new HttpRequestException("vault is down") }
            .Set("mongo", 1, """{"Connection": "a"}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.Optional = true;
        options.LoadTimeoutSeconds = 1;
        options.ReconnectIntervalSeconds = 1;

        using var provider = new VaultConfigurationProvider(options, reader);
        provider.Load();
        var reloaded = false;
        provider.GetReloadToken().RegisterChangeCallback(_ => reloaded = true, null);

        reader.Failure = null;
        await provider.ReloadAsync(CancellationToken.None);

        Assert.True(provider.TryGet("mongo:Connection", out var connection));
        Assert.Equal("a", connection);
        Assert.True(reloaded);
    }

    [Fact]
    public async Task Load_FailingRequiredLoadLeavesNoRefreshBehind()
    {
        var reader = new FakeVaultReader { Failure = new HttpRequestException("vault is down") };
        var options = Options(new VaultSecret(Path: "mongo"));
        options.LoadTimeoutSeconds = 1;
        options.ReconnectIntervalSeconds = 1;
        options.ReloadCheckIntervalSeconds = 1;

        var provider = new VaultConfigurationProvider(options, reader);
        Assert.Throws<TimeoutException>(provider.Load);

        var afterFailure = reader.Attempts;
        await Task.Delay(TimeSpan.FromSeconds(2.5));

        Assert.Equal(afterFailure, reader.Attempts);
    }

    [Fact]
    public async Task Dispose_StopsTheBackgroundRefresh()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a"}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.ReloadCheckIntervalSeconds = 1;

        var provider = Loaded(options, reader);
        provider.Dispose();

        var afterDispose = reader.VersionReads;
        await Task.Delay(TimeSpan.FromSeconds(2.5));

        Assert.Equal(afterDispose, reader.VersionReads);
    }

    [Fact]
    public async Task Refresh_SlowReaderDoesNotOverlapTheNextCycle()
    {
        var reader = new FakeVaultReader { Latency = TimeSpan.FromMilliseconds(400) }
            .Set("mongo", 1, """{"Connection": "a"}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.ReloadCheckIntervalSeconds = 1;

        using var provider = Loaded(options, reader);
        await Task.Delay(TimeSpan.FromSeconds(3));

        Assert.InRange(reader.VersionReads, 1, 3);
    }
}
