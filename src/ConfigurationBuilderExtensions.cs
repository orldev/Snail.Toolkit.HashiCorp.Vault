using Microsoft.Extensions.Configuration;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Configuration builder entry points for the Vault source.</summary>
public static class ConfigurationBuilderExtensions
{
    extension(IConfigurationBuilder configuration)
    {
        /// <summary>Adds Vault secrets to the configuration with explicitly built options.</summary>
        public IConfigurationBuilder AddVault(Action<VaultOptions> options)
        {
            var vaultOptions = new VaultOptions();
            options.Invoke(vaultOptions);

            return configuration.AddVault(vaultOptions);
        }

        /// <summary>Adds Vault secrets to the configuration with ready options.</summary>
        /// <remarks>
        /// <see cref="VaultOptions.KeepExistingValues"/> decides where the source lands: ahead of every
        /// other one so anything else overrides it, or last so Vault wins.
        /// </remarks>
        public IConfigurationBuilder AddVault(VaultOptions options)
        {
            var source = new VaultConfigurationSource(options);

            if (options.KeepExistingValues)
                configuration.Sources.Insert(0, source);
            else
                configuration.Sources.Add(source);

            return configuration;
        }

        /// <summary>Adds Vault secrets with the options taken from the "Vault" section of the configuration built so far.</summary>
        public IConfigurationBuilder AddVault()
        {
            var root = configuration.Build();
            var options = root.GetSection("Vault").Get<VaultOptions>();

            if (!ReferenceEquals(root, configuration) && root is IDisposable snapshot)
                snapshot.Dispose();

            return configuration.AddVault(options
                ?? throw new InvalidOperationException("Vault: the 'Vault' configuration section is missing."));
        }
    }
}
