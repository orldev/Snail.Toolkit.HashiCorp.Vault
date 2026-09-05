namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Thrown when a requested secret does not exist in Vault.</summary>
/// <param name="path">Path the configuration asked for.</param>
/// <param name="innerException">The refusal from the server, kept so its status and body survive the translation.</param>
public sealed class SecretNotFoundException(string? path, Exception? innerException = null)
    : Exception($"Secret not found: {path}", innerException)
{
    /// <summary>Path the configuration asked for.</summary>
    public string? Path { get; } = path;
}
