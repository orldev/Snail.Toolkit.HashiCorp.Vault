using System.Text.Json.Nodes;
using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

internal sealed class FakeVaultReader : IVaultReader
{
    private readonly Dictionary<string, Kv2Secret> _secrets = new();

    public int SecretReads { get; private set; }

    public int VersionReads { get; private set; }

    public Exception? Failure { get; set; }

    public FakeVaultReader Set(string path, int version, string json)
    {
        _secrets[path] = new Kv2Secret((JsonObject)JsonNode.Parse(json)!, version);
        return this;
    }

    public Task<Kv2Secret> ReadSecretAsync(VaultSecret secret, CancellationToken cancellationToken = default)
    {
        if (Failure is not null)
            throw Failure;

        SecretReads++;
        return Task.FromResult(_secrets[secret.Path!]);
    }

    public Task<int> ReadSecretVersionAsync(VaultSecret secret, CancellationToken cancellationToken = default)
    {
        if (Failure is not null)
            throw Failure;

        VersionReads++;
        return Task.FromResult(_secrets[secret.Path!].Version);
    }
}
