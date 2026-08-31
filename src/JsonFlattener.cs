using System.Text.Json;
using System.Text.Json.Nodes;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Turns a JSON value into flat configuration pairs: members become segments, array elements become indexes.</summary>
internal static class JsonFlattener
{
    public static string Combine(string prefix, string key) =>
        string.IsNullOrEmpty(prefix) ? key : $"{prefix}:{key}";

    public static IReadOnlyDictionary<string, string?> Flatten(string prefix, JsonNode? node)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        Walk(prefix, node, result);
        return result;
    }

    /// <summary>Unwraps a string value carrying a JSON document, so its structure lands as sections rather than one opaque string.</summary>
    public static JsonNode? Expand(JsonNode? node)
    {
        if (node is not JsonValue value || !value.TryGetValue<string>(out var text))
            return node;

        var trimmed = text.TrimStart();
        if (!trimmed.StartsWith('{') && !trimmed.StartsWith('['))
            return node;

        try
        {
            return JsonNode.Parse(text);
        }
        catch (JsonException)
        {
            return node;
        }
    }

    private static void Walk(string prefix, JsonNode? node, Dictionary<string, string?> into)
    {
        switch (node)
        {
            case JsonObject jsonObject:
                foreach (var (key, child) in jsonObject)
                    Walk(Combine(prefix, key), child, into);
                break;
            case JsonArray jsonArray:
                for (var i = 0; i < jsonArray.Count; i++)
                    Walk(Combine(prefix, i.ToString()), jsonArray[i], into);
                break;
            case JsonValue jsonValue:
                into[prefix] = jsonValue.ToString();
                break;
            case null:
                into[prefix] = null;
                break;
        }
    }
}
