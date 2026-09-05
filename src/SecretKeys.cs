using System.Text.Json.Nodes;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>The configuration keys one secret contributes, and the values behind them.</summary>
internal static class SecretKeys
{
    /// <summary>Maps a secret's payload onto configuration keys, refusing to let two of its keys claim one.</summary>
    /// <remarks>
    /// Configuration keys are compared case-insensitively and ':' separates sections, so 'Token' and
    /// 'TOKEN', or a key literally named 'Db:Password', can land on the same configuration key as another.
    /// Whichever Vault enumerated last would win and the other secret would be gone with nothing said,
    /// which for a secret is worse than refusing to start.
    /// </remarks>
    public static IReadOnlyDictionary<string, string?> Of(
        VaultSecret secret, JsonObject payload, bool expandJsonValues)
    {
        var prefix = secret.ConfigurationPrefix ?? secret.Path ?? string.Empty;
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var claimedBy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (key, node) in payload)
        {
            if (string.IsNullOrEmpty(key))
                continue;

            if (secret.Keys is { Count: > 0 } && !secret.Keys.Contains(key, StringComparer.OrdinalIgnoreCase))
                continue;

            var content = expandJsonValues ? JsonFlattener.Expand(node) : node;

            foreach (var (path, value) in JsonFlattener.Flatten(JsonFlattener.Combine(prefix, key), content))
            {
                if (!claimedBy.TryAdd(path, key))
                    throw new InvalidOperationException(
                        $"Vault: the secret '{secret.Path}' maps both '{claimedBy[path]}' and '{key}' onto " +
                        $"the configuration key '{path}', so one would silently replace the other.");

                values[path] = value;
            }
        }

        return values;
    }
}
