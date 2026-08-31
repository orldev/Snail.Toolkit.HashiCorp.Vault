global using Xunit;
using Microsoft.Extensions.Configuration;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

public class VaultConfigurationProviderTests
{
    private static VaultOptions Options(params VaultSecret[] secrets) => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        Logger = (_, _) => { },
        Secrets = secrets,
    };

    private static IConfigurationRoot EmptyRoot() => new ConfigurationBuilder().Build();

    private static VaultConfigurationProvider Loaded(VaultOptions options, FakeVaultReader reader,
        IConfigurationRoot? root = null)
    {
        var provider = new VaultConfigurationProvider(options, root ?? EmptyRoot(), reader);
        provider.Load();
        return provider;
    }

    [Fact]
    public void Load_MapsSecretUnderItsPathByDefault()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "mongodb://localhost:27017", "Database": "keynex"}""");

        using var provider = Loaded(Options(new VaultSecret(path: "mongo")), reader);

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
            Options(new VaultSecret(path: "keynex/assets", configurationPrefix: "Assets")), reader);

        Assert.True(provider.TryGet("Assets:SecretKey", out var value));
        Assert.Equal("cipher-key", value);
    }

    [Fact]
    public void Load_EmptyPrefixMapsKeysToTheRoot()
    {
        var reader = new FakeVaultReader()
            .Set("shared", 1, """{"Seq": "http://seq:5341"}""");

        using var provider = Loaded(
            Options(new VaultSecret(path: "shared", configurationPrefix: "")), reader);

        Assert.True(provider.TryGet("Seq", out var value));
        Assert.Equal("http://seq:5341", value);
    }

    [Fact]
    public void Load_KeysFilterIsCaseInsensitive()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a", "Database": "b"}""");

        using var provider = Loaded(
            Options(new VaultSecret(path: "mongo", keys: ["connection"])), reader);

        Assert.True(provider.TryGet("mongo:Connection", out _));
        Assert.False(provider.TryGet("mongo:Database", out _));
    }

    [Fact]
    public void Load_KeepExistingValuesLeavesEarlierProvidersInCharge()
    {
        var root = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["mongo:Connection"] = "from-appsettings" })
            .Build();
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "from-vault", "Database": "keynex"}""");
        var options = Options(new VaultSecret(path: "mongo"));
        options.KeepExistingValues = true;

        using var provider = Loaded(options, reader, root);

        Assert.False(provider.TryGet("mongo:Connection", out _));
        Assert.True(provider.TryGet("mongo:Database", out _));
    }

    [Fact]
    public void Load_NestedJsonAndScalarArraysBecomeSections()
    {
        var reader = new FakeVaultReader()
            .Set("app", 1, """{"Nested": {"Inner": {"Value": "x"}, "Hosts": ["a", "b"]}}""");

        using var provider = Loaded(Options(new VaultSecret(path: "app")), reader);

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

        using var provider = Loaded(Options(new VaultSecret(path: "app")), reader);

        Assert.True(provider.TryGet("app:Serilog:MinimumLevel", out var level));
        Assert.Equal("Debug", level);
    }

    [Fact]
    public void Load_OptionalSourceSwallowsTheFailure()
    {
        var reader = new FakeVaultReader { Failure = new HttpRequestException("vault is down") };
        var options = Options(new VaultSecret(path: "mongo"));
        options.Optional = true;
        options.LoadTimeoutSeconds = 1;
        options.ReconnectIntervalSeconds = 0;

        using var provider = new VaultConfigurationProvider(options, EmptyRoot(), reader);
        provider.Load();

        Assert.False(provider.TryGet("mongo:Connection", out _));
    }

    [Fact]
    public void Load_RequiredSourceFailsWithTimeout()
    {
        var reader = new FakeVaultReader { Failure = new HttpRequestException("vault is down") };
        var options = Options(new VaultSecret(path: "mongo"));
        options.LoadTimeoutSeconds = 1;
        options.ReconnectIntervalSeconds = 0;

        using var provider = new VaultConfigurationProvider(options, EmptyRoot(), reader);

        Assert.Throws<TimeoutException>(provider.Load);
    }

    [Fact]
    public void Load_MissingSecretIsAConfigurationError()
    {
        var reader = new FakeVaultReader { Failure = new SecretNotFoundException("mongo") };
        var options = Options(new VaultSecret(path: "mongo"));

        using var provider = new VaultConfigurationProvider(options, EmptyRoot(), reader);

        Assert.Throws<SecretNotFoundException>(provider.Load);
    }

    [Fact]
    public async Task Reload_SkipsTheReadWhenTheVersionHasNotMoved()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a"}""");

        using var provider = Loaded(Options(new VaultSecret(path: "mongo")), reader);
        await provider.ReloadAsync(CancellationToken.None);

        Assert.Equal(1, reader.SecretReads);
        Assert.Equal(1, reader.VersionReads);
    }

    [Fact]
    public async Task Reload_PicksUpANewVersionAndRaisesTheToken()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a"}""");

        using var provider = Loaded(Options(new VaultSecret(path: "mongo")), reader);
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

        using var provider = Loaded(Options(new VaultSecret(path: "mongo")), reader);
        var reloaded = false;
        provider.GetReloadToken().RegisterChangeCallback(_ => reloaded = true, null);

        reader.Set("mongo", 2, """{"Connection": "a"}""");
        await provider.ReloadAsync(CancellationToken.None);

        Assert.False(reloaded);
    }

    [Fact]
    public void AddVault_BindsOptionsFromTheVaultSection()
    {
        var builder = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Address"] = "http://127.0.0.1:1",
            ["Vault:Token"] = "root",
            ["Vault:MountPath"] = "secret",
            ["Vault:LoadTimeoutSeconds"] = "1",
            ["Vault:ReconnectIntervalSeconds"] = "0",
            ["Vault:Secrets:0:Path"] = "mongo",
            ["Vault:Secrets:0:ConfigurationPrefix"] = "Mongo",
        });

        Assert.Throws<TimeoutException>(() => builder.AddVault().Build());
    }
}
