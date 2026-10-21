namespace Snail.Toolkit.HashiCorp.Vault.Tests.Chaos;

/// <summary>Keys names what the application needs from a secret, and a secret without one of them is refused.</summary>
public class KeysContractTests
{
    private static VaultOptions Options(params VaultSecret[] secrets) => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        Logger = (_, _) => { },
        Secrets = secrets,
    };

    /// <summary>
    /// A key named in Keys and absent from the secret would otherwise be dropped with nothing said, and the
    /// application would fail later, far from the cause, on a value that is null.
    /// </summary>
    [Fact]
    public void Load_KeyListedButAbsentFromTheSecret_IsRefused()
    {
        var reader = new FakeVaultReader().Set("mongo", 1, """{"Connection": "a"}""");
        var options = Options(new VaultSecret(Path: "mongo", Keys: ["Connection", "Database"]));
        using var provider = new VaultConfigurationProvider(options, reader);

        var error = Record.Exception(provider.Load);

        var refusal = Assert.IsType<InvalidOperationException>(error);
        Assert.Contains("Database", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>A Vault source with no secrets is a binding mistake, not a request for nothing: the start refuses.</summary>
    [Fact]
    public void Validate_NoSecretsConfigured_IsRefused()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => new VaultConfigurationProvider(Options(), new FakeVaultReader()));

        Assert.Contains(nameof(VaultOptions.Secrets), error.Message, StringComparison.Ordinal);
    }
}
