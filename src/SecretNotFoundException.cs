namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Thrown when a requested secret does not exist in Vault.</summary>
public class SecretNotFoundException(string? path) : Exception($"Secret not found: {path}");
