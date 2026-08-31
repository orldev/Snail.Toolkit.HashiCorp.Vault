namespace Snail.Toolkit.HashiCorp.Vault.Http;

/// <summary>Reads KV v2 secrets from a Vault server.</summary>
public interface IVaultReader
{
    /// <summary>Reads the secret the declaration points at.</summary>
    Task<Kv2Secret> ReadSecretAsync(VaultSecret secret, CancellationToken cancellationToken = default);

    /// <summary>Reads the secret's current version — a cheap probe deciding whether a reload is worth the full read.</summary>
    Task<int> ReadSecretVersionAsync(VaultSecret secret, CancellationToken cancellationToken = default);
}
