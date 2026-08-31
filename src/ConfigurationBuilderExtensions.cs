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
        public IConfigurationBuilder AddVault(VaultOptions options)
        {
            configuration.Add(new VaultConfigurationSource(options, configuration.Build()));
            return configuration;
        }

        /// <summary>Adds Vault secrets with the options taken from the "Vault" section of the configuration built so far.</summary>
        public IConfigurationBuilder AddVault()
        {
            var root = configuration.Build();
            var options = root.GetSection("Vault").Get<VaultOptions>()
                ?? throw new InvalidOperationException("Vault: the 'Vault' configuration section is missing.");

            configuration.Add(new VaultConfigurationSource(options, root));
            return configuration;
        }

        /// <summary>Adds appsettings, environment variables and Vault in one call — for builders that start from an empty configuration.</summary>
        public IConfigurationBuilder AddVaultWithAppSettings()
        {
            var env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ??
                Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");

            return configuration
                .AddJsonFile("appsettings.json", optional: true)
                .AddJsonFile($"appsettings.{env}.json", optional: true)
                .AddEnvironmentVariables()
                .AddVault();
        }
    }
}
