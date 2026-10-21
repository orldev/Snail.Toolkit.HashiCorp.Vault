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
        RequireEveryKey(secret, payload);

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

    /// <summary>Refuses a secret that lacks a key <see cref="VaultSecret.Keys"/> names.</summary>
    /// <remarks>
    /// Keys says what the application needs from the secret, not what it would take if offered. A key named
    /// there and absent from the secret would be dropped with nothing said, and the application would fail
    /// later, far from the cause, on a value that is null: the outcome the refusal of colliding keys exists
    /// to prevent.
    /// </remarks>
    private static void RequireEveryKey(VaultSecret secret, JsonObject payload)
    {
        if (secret.Keys is not { Count: > 0 } wanted)
            return;

        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, _) in payload)
            present.Add(key);

        var missing = new List<string>();
        foreach (var key in wanted)
        {
            if (!present.Contains(key))
                missing.Add(key);
        }

        if (missing.Count == 0)
            return;

        throw new InvalidOperationException(
            $"Vault: the secret '{secret.Path}' has no key '{string.Join("', '", missing)}' that " +
            $"'{nameof(VaultSecret.Keys)}' names.");
    }
}
