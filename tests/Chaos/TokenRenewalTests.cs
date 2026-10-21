using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault.Tests.Chaos;

/// <summary>How many AppRole logins a refusal costs: one per lease, never one per request or per interval.</summary>
public class TokenRenewalTests
{
    private static VaultOptions AppRole(params VaultSecret[] secrets) => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        RoleId = "role",
        SecretId = "secret",
        Logger = (_, _) => { },
        Secrets = secrets,
    };

    private static VaultHttpClient Client(VaultOptions options, HttpMessageHandler handler) =>
        new(options, new HttpClient(handler) { BaseAddress = new Uri("http://vault.local:8200/") });

    /// <summary>
    /// A read the policy denies answers 403 to a fresh token as it did to the old one. One login tells an
    /// expired token from a policy without the path; a second one per retry would spend an AppRole's
    /// secret_id_num_uses on a configuration error.
    /// </summary>
    [Fact]
    public void Load_ReadDeniedByPolicy_DoesNotLogInOnEveryRetry()
    {
        var handler = new DenyingVaultHandler(deniesData: true);
        var options = AppRole(new VaultSecret(Path: "mongo"));
        options.LoadTimeoutSeconds = 3;
        options.ReconnectIntervalSeconds = 1;
        using var reader = Client(options, handler);
        using var provider = new VaultConfigurationProvider(options, reader);

        Record.Exception(provider.Load);

        Assert.InRange(handler.Logins, 1, 2);
    }

    /// <summary>
    /// The version probe is the request a read-only policy most often denies, and the provider falls back to
    /// the full read. The 403 of the probe buys no new token: taken for an expired one, it would log in on
    /// every reload interval, a fresh Vault token per interval for the life of the process.
    /// </summary>
    [Fact]
    public async Task Reload_VersionProbeDeniedByPolicy_LogsInOnce()
    {
        var handler = new DenyingVaultHandler(deniesMetadata: true);
        var options = AppRole(new VaultSecret(Path: "mongo"));
        using var reader = Client(options, handler);
        using var provider = new VaultConfigurationProvider(options, reader);
        provider.Load();

        for (var cycle = 0; cycle < 5; cycle++)
            await provider.ReloadAsync(CancellationToken.None);

        Assert.Equal(1, handler.Logins);
    }
}
