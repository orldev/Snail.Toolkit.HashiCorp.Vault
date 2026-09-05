using Microsoft.Extensions.Configuration;
using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Configuration source that reads secrets from Vault.</summary>
public sealed class VaultConfigurationSource(VaultOptions options, IVaultReader? reader = null) : IConfigurationSource
{
    /// <summary>Creates the source from an options delegate.</summary>
    public VaultConfigurationSource(Action<VaultOptions> options)
        : this(Create(options))
    {
    }

    /// <inheritdoc/>
    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new VaultConfigurationProvider(options, reader);

    private static VaultOptions Create(Action<VaultOptions> options)
    {
        var vaultOptions = new VaultOptions();
        options.Invoke(vaultOptions);
        return vaultOptions;
    }
}
