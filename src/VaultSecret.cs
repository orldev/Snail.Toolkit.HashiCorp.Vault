namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>One secret to read and the configuration section it lands in.</summary>
/// <param name="Path">Path of the secret inside the mount.</param>
/// <param name="Keys">Keys to take from the secret, compared case-insensitively; every key when not set.</param>
/// <param name="MountPath">Mount point overriding <see cref="VaultOptions.MountPath"/>.</param>
/// <param name="Version">Secret version to pin; the latest when not set.</param>
/// <param name="ConfigurationPrefix">Configuration section for the keys: <paramref name="Path"/> when not set, the root when empty.</param>
public sealed record VaultSecret(
    string? Path = null,
    IReadOnlyList<string>? Keys = null,
    string? MountPath = null,
    int? Version = null,
    string? ConfigurationPrefix = null);
