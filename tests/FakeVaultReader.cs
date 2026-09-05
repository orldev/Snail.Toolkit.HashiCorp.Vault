using System.Text.Json.Nodes;
using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

internal sealed class FakeVaultReader : IVaultReader
{
    private readonly Dictionary<string, Kv2Secret> _secrets = new();
    private int _attempts;
    private int _secretReads;
    private int _versionReads;

    /// <summary>Every call that reached the reader, whether it went on to succeed or to fail.</summary>
    public int Attempts => Volatile.Read(ref _attempts);

    public int SecretReads => Volatile.Read(ref _secretReads);

    public int VersionReads => Volatile.Read(ref _versionReads);

    public Exception? Failure { get; set; }

    public Exception? VersionFailure { get; set; }

    public TimeSpan Latency { get; set; }

    /// <summary>Makes the reader deaf to the caller's token, the way a client that swallows it would be.</summary>
    public bool IgnoresCancellation { get; set; }

    /// <summary>Fails one secret while the others answer, so a load can break part of the way through.</summary>
    public Dictionary<string, Exception> FailuresByPath { get; } = new(StringComparer.Ordinal);

    public FakeVaultReader Set(string path, int? version, string json)
    {
        _secrets[path] = new Kv2Secret((JsonObject)JsonNode.Parse(json)!, version);
        return this;
    }

    public async Task<Kv2Secret> ReadSecretAsync(VaultSecret secret, CancellationToken cancellationToken = default)
    {
        await RespondAsync(cancellationToken);

        if (FailuresByPath.TryGetValue(secret.Path!, out var failure))
            throw failure;

        Interlocked.Increment(ref _secretReads);
        return _secrets[secret.Path!];
    }

    public async Task<int?> ReadSecretVersionAsync(VaultSecret secret, CancellationToken cancellationToken = default)
    {
        await RespondAsync(cancellationToken);

        if (VersionFailure is not null)
            throw VersionFailure;

        Interlocked.Increment(ref _versionReads);
        return _secrets[secret.Path!].Version;
    }

    private async Task RespondAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _attempts);

        if (Latency > TimeSpan.Zero)
            await Task.Delay(Latency, IgnoresCancellation ? CancellationToken.None : cancellationToken);

        if (Failure is not null)
            throw Failure;
    }
}
