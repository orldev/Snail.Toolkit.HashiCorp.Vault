using Microsoft.Extensions.Configuration;

namespace Snail.Toolkit.HashiCorp.Vault.Tests.Integration;

public class VaultIntegrationTests(VaultContainerFixture vault) : IClassFixture<VaultContainerFixture>
{
    private VaultOptions Options(params VaultSecret[] secrets) => new()
    {
        Address = vault.Address,
        MountPath = "secret",
        Logger = (_, _) => { },
        Secrets = secrets,
    };

    [DockerFact]
    public async Task TokenAuth_ReadsASecretIntoTheConfiguration()
    {
        await vault.ExecAsync("vault kv put secret/it-mongo Connection=mongodb://mongo:27017 Database=keynex");

        var options = Options(new VaultSecret(Path: "it-mongo"));
        options.Token = VaultContainerFixture.RootToken;

        var configuration = new ConfigurationBuilder().AddVault(options).Build();

        Assert.Equal("mongodb://mongo:27017", configuration["it-mongo:Connection"]);
        Assert.Equal("keynex", configuration["it-mongo:Database"]);
    }

    [DockerFact]
    public async Task AppRole_ReadsASecretIntoTheConfiguration()
    {
        await vault.ExecAsync("vault kv put secret/it-approle SecretKey=cipher");

        var options = Options(new VaultSecret(Path: "it-approle", ConfigurationPrefix: "Assets"));
        options.RoleId = vault.RoleId;
        options.SecretId = vault.SecretId;

        var configuration = new ConfigurationBuilder().AddVault(options).Build();

        Assert.Equal("cipher", configuration["Assets:SecretKey"]);
    }

    [DockerFact]
    public async Task PinnedVersion_StaysOnTheOldValue()
    {
        await vault.ExecAsync("vault kv put secret/it-pinned Value=first");
        await vault.ExecAsync("vault kv put secret/it-pinned Value=second");

        var options = Options(new VaultSecret(Path: "it-pinned", Version: 1));
        options.Token = VaultContainerFixture.RootToken;

        var configuration = new ConfigurationBuilder().AddVault(options).Build();

        Assert.Equal("first", configuration["it-pinned:Value"]);
    }

    [DockerFact]
    public async Task Reload_PicksUpARotatedSecret()
    {
        await vault.ExecAsync("vault kv put secret/it-reload Value=before");

        var options = Options(new VaultSecret(Path: "it-reload"));
        options.Token = VaultContainerFixture.RootToken;
        options.ReloadCheckIntervalSeconds = 1;

        var configuration = new ConfigurationBuilder().AddVault(options).Build();
        Assert.Equal("before", configuration["it-reload:Value"]);

        await vault.ExecAsync("vault kv put secret/it-reload Value=after");

        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (configuration["it-reload:Value"] != "after" && DateTime.UtcNow < deadline)
            await Task.Delay(250);

        Assert.Equal("after", configuration["it-reload:Value"]);
    }

    [DockerFact]
    public void Optional_StartsWithoutAReachableVault()
    {
        var options = Options(new VaultSecret(Path: "it-optional"));
        options.Address = "http://127.0.0.1:1";
        options.Token = VaultContainerFixture.RootToken;
        options.Optional = true;
        options.LoadTimeoutSeconds = 2;
        options.ReconnectIntervalSeconds = 1;

        var configuration = new ConfigurationBuilder().AddVault(options).Build();

        Assert.Null(configuration["it-optional:Value"]);
    }
}
