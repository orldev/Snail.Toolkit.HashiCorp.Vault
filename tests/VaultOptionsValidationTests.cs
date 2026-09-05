
namespace Snail.Toolkit.HashiCorp.Vault.Tests;

/// <summary>Options the provider refuses to start on.</summary>
public class VaultOptionsValidationTests
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
    public void Validate_SecretWithoutAPathIsRejected()
    {
        var options = Options(new VaultSecret());

        var error = Assert.Throws<InvalidOperationException>(
            () => new VaultConfigurationProvider(options, new FakeVaultReader()));

        Assert.Contains(nameof(VaultSecret.Path), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RetryIntervalBelowASecondIsRejected()
    {
        var options = Options(new VaultSecret(Path: "mongo"));
        options.ReconnectIntervalSeconds = 0;

        var error = Assert.Throws<InvalidOperationException>(
            () => new VaultConfigurationProvider(options, new FakeVaultReader()));

        Assert.Contains(nameof(VaultOptions.ReconnectIntervalSeconds), error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Guards the rule rather than the cases: an interval option added later must be validated too,
    /// and this fails until it is.
    /// </summary>

    [Fact]
    public void Validate_EveryIntervalOptionIsChecked()
    {
        var intervals = typeof(VaultOptions).GetProperties()
            .Where(property => property.Name.EndsWith("Seconds", StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(intervals);

        foreach (var interval in intervals)
        {
            var options = Options(new VaultSecret(Path: "mongo"));
            interval.SetValue(options, 0);

            var error = Assert.Throws<InvalidOperationException>(
                () => new VaultConfigurationProvider(options, new FakeVaultReader()));

            Assert.Contains(interval.Name, error.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Validate_MissingAddressIsRejectedBeforeAnyRequest()
    {
        var options = Options(new VaultSecret(Path: "mongo"));
        options.Address = null;

        var error = Assert.Throws<InvalidOperationException>(
            () => new VaultConfigurationProvider(options));

        Assert.Contains(nameof(VaultOptions.Address), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_MissingCredentialsAreRejectedBeforeAnyRequest()
    {
        var options = Options(new VaultSecret(Path: "mongo"));

        var error = Assert.Throws<InvalidOperationException>(
            () => new VaultConfigurationProvider(options));

        Assert.Contains(nameof(VaultOptions.RoleId), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_InjectedReaderMakesTransportSettingsIrrelevant()
    {
        var reader = new FakeVaultReader()
            .Set("mongo", 1, """{"Connection": "a"}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.Address = null;

        using var provider = Loaded(options, reader);

        Assert.True(provider.TryGet("mongo:Connection", out _));
    }
}
