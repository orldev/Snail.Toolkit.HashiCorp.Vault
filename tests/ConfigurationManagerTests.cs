using Microsoft.Extensions.Configuration;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

public class ConfigurationManagerTests
{
    /// <summary>
    /// builder.Configuration in a host is a ConfigurationManager, whose Build returns itself, so anything
    /// AddVault does to what Build handed back it does to the application's own configuration.
    /// </summary>
    [Fact]
    public void AddVault_OnAConfigurationManagerLeavesItUsable()
    {
        var manager = new ConfigurationManager();
        manager.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Address"] = "http://127.0.0.1:1",
            ["Vault:Token"] = "root",
            ["Vault:MountPath"] = "secret",
            ["Vault:Optional"] = "true",
            ["Vault:LoadTimeoutSeconds"] = "1",
            ["Vault:ReconnectIntervalSeconds"] = "1",
            ["Vault:Secrets:0:Path"] = "mongo",
        });

        manager.AddVault();

        Assert.Equal("secret", manager["Vault:MountPath"]);
    }
}
