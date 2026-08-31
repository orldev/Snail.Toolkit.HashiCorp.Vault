namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>One secret to read and the configuration section it lands in.</summary>
public class VaultSecret(
    string? path = null,
    string[]? keys = null,
    string? mountPath = null,
    int? version = null,
    string? configurationPrefix = null)
{
    /// <summary>Path of the secret inside the mount.</summary>
    public string? Path { get; } = path;

    /// <summary>Keys to take from the secret, compared case-insensitively; every key when not set.</summary>
    public string[]? Keys { get; } = keys;

    /// <summary>Mount point overriding <see cref="VaultOptions.MountPath"/>.</summary>
    public string? MountPath { get; } = mountPath;

    /// <summary>Secret version to pin; the latest when not set.</summary>
    public int? Version { get; } = version;

    /// <summary>Configuration section for the keys: <see cref="Path"/> when not set, the root when empty.</summary>
    public string? ConfigurationPrefix { get; } = configurationPrefix;
}
