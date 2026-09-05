using Microsoft.Extensions.Configuration;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

/// <summary>Where AddVault puts the source, and how the Vault section binds.</summary>
public class ConfigurationBuilderExtensionsTests
{
    private static VaultOptions Options(params VaultSecret[] secrets) => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        Logger = (_, _) => { },
        Secrets = secrets,
    };

    private static VaultOptions Credentialed(params VaultSecret[] secrets)
    {
        var options = Options(secrets);
        options.Token = "root";
        return options;
    }

    /// <summary>Builds a configuration where the named keys already come from another source.</summary>
    private static IConfigurationRoot Built(VaultOptions options, FakeVaultReader reader, string[] existing)
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(existing.ToDictionary(key => key, key => (string?)"from-appsettings"));
        var source = new VaultConfigurationSource(options, reader);

        if (options.KeepExistingValues)
            builder.Sources.Insert(0, source);
        else
            builder.Sources.Add(source);

        return builder.Build();
    }

    [Fact]
    public void KeepExistingValues_LeavesTheOtherSourcesInCharge()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "from-vault", "Database": "keynex"}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.KeepExistingValues = true;

        var configuration = Built(options, reader, ["mongo:Connection"]);

        Assert.Equal("from-appsettings", configuration["mongo:Connection"]);
        Assert.Equal("keynex", configuration["mongo:Database"]);
    }

    [Fact]
    public void KeepExistingValues_TurnedOffLetsVaultWin()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "from-vault"}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.KeepExistingValues = false;

        var configuration = Built(options, reader, ["mongo:Connection"]);

        Assert.Equal("from-vault", configuration["mongo:Connection"]);
    }

    [Fact]
    public void AddVault_KeepingExistingValuesPutsTheSourceAhead()
    {
        var builder = new ConfigurationBuilder().AddInMemoryCollection([]);

        builder.AddVault(Credentialed(new VaultSecret(Path: "mongo")));

        Assert.IsType<VaultConfigurationSource>(builder.Sources[0]);
    }

    [Fact]
    public void AddVault_FromADelegateRegistersTheSource()
    {
        var builder = new ConfigurationBuilder();

        builder.AddVault(options =>
        {
            options.Address = "http://127.0.0.1:8200";
            options.Token = "root";
            options.MountPath = "secret";
            options.Secrets = [new VaultSecret(Path: "mongo")];
        });

        Assert.IsType<VaultConfigurationSource>(Assert.Single(builder.Sources));
    }

    [Fact]
    public void AddVault_WithoutKeepingExistingValuesPutsTheSourceLast()
    {
        var builder = new ConfigurationBuilder().AddInMemoryCollection([]);
        var options = Credentialed(new VaultSecret(Path: "mongo"));
        options.KeepExistingValues = false;

        builder.AddVault(options);

        Assert.IsType<VaultConfigurationSource>(builder.Sources[^1]);
    }

    [Fact]
    public void VaultSection_BindsEverySettingOfASecret()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Address"] = "http://127.0.0.1:8200",
            ["Vault:MountPath"] = "secret",
            ["Vault:ExpandJsonValues"] = "false",
            ["Vault:Secrets:0:Path"] = "mongo",
            ["Vault:Secrets:0:ConfigurationPrefix"] = "Mongo",
            ["Vault:Secrets:0:MountPath"] = "team",
            ["Vault:Secrets:0:Version"] = "4",
            ["Vault:Secrets:0:Keys:0"] = "Connection",
            ["Vault:Secrets:0:Keys:1"] = "Database",
        }).Build();

        var options = configuration.GetSection("Vault").Get<VaultOptions>();

        Assert.NotNull(options);
        Assert.False(options.ExpandJsonValues);
        var secret = Assert.Single(options.Secrets!);
        Assert.Equal("mongo", secret.Path);
        Assert.Equal("Mongo", secret.ConfigurationPrefix);
        Assert.Equal("team", secret.MountPath);
        Assert.Equal(4, secret.Version);
        Assert.Equal(["Connection", "Database"], secret.Keys);
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
            ["Vault:ReconnectIntervalSeconds"] = "1",
            ["Vault:Secrets:0:Path"] = "mongo",
            ["Vault:Secrets:0:ConfigurationPrefix"] = "Mongo",
        });

        Assert.Throws<TimeoutException>(() => builder.AddVault().Build());
    }
}
