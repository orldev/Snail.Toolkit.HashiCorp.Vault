namespace Snail.Toolkit.HashiCorp.Vault.Tests.Chaos;

/// <summary>The change token is raised outside the load gate, so what a change callback does cannot deadlock the provider.</summary>
public class ReloadGateTests
{
    /// <summary>
    /// A change callback that loads again, as IConfigurationRoot.Reload does, completes within one load rather
    /// than waiting for its own caller until the budget runs out and being handed a timeout that blames Vault.
    /// </summary>
    [Fact]
    public async Task Reload_ChangeCallbackThatLoadsAgain_IsNotHeldForTheWholeBudget()
    {
        var reader = new FakeVaultReader().Set("mongo", 1, """{"Connection": "a"}""");
        var options = new VaultOptions
        {
            Address = "http://vault.local:8200",
            MountPath = "secret",
            LoadTimeoutSeconds = 1,
            Logger = (_, _) => { },
            Secrets = [new VaultSecret(Path: "mongo")],
        };
        using var provider = new VaultConfigurationProvider(options, reader);
        provider.Load();
        Exception? nested = null;
        provider.GetReloadToken().RegisterChangeCallback(_ => nested = Record.Exception(provider.Load), null);

        reader.Set("mongo", 2, """{"Connection": "b"}""");
        await provider.ReloadAsync(CancellationToken.None);

        Assert.Null(nested);
    }
}
