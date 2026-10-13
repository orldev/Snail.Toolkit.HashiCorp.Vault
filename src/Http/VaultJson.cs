using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Snail.Toolkit.HashiCorp.Vault.Http;

/// <summary>The part of a KV v2 metadata answer the version probe reads.</summary>
/// <param name="Metadata">The metadata, under <c>data</c>.</param>
internal sealed record MetadataAnswer([property: JsonPropertyName("data")] SecretMetadata? Metadata);

/// <summary>The current version of a secret, the one field of its metadata the probe needs.</summary>
/// <param name="CurrentVersion">The version a read without a pinned version returns.</param>
/// <remarks>The version history beside it is skipped, not built into a tree.</remarks>
internal sealed record SecretMetadata([property: JsonPropertyName("current_version")] int? CurrentVersion);

/// <summary>The part of a KV v2 data answer the secret read keeps.</summary>
/// <param name="Content">The secret and its metadata, under <c>data</c>.</param>
internal sealed record SecretAnswer(
    [property: JsonPropertyName("data"), JsonConverter(typeof(ObjectOnlyConverter<SecretContent>))]
    SecretContent? Content);

/// <summary>A secret as KV v2 answers it: the payload and the version it was read at.</summary>
/// <param name="Data">The payload; only an object is a secret.</param>
/// <param name="Metadata">The metadata beside it.</param>
/// <remarks>The payload alone stays a tree, since its keys are the secret's own.</remarks>
internal sealed record SecretContent(
    JsonNode? Data,
    [property: JsonConverter(typeof(ObjectOnlyConverter<SecretStamp>))] SecretStamp? Metadata);

/// <summary>The version a secret was read at.</summary>
/// <param name="Version">The version, null when the server did not state one.</param>
internal sealed record SecretStamp([property: JsonConverter(typeof(IntegerOnlyConverter))] int? Version);

/// <summary>The part of an AppRole login answer the client keeps.</summary>
/// <param name="Auth">The token granted and its lease.</param>
internal sealed record LoginAnswer(
    [property: JsonConverter(typeof(ObjectOnlyConverter<LoginGrant>))] LoginGrant? Auth);

/// <summary>The token an AppRole login grants and how long it lives.</summary>
/// <param name="ClientToken">The token requests carry.</param>
/// <param name="LeaseDuration">Its lease in seconds; zero or none is a token that does not expire.</param>
internal sealed record LoginGrant(
    [property: JsonPropertyName("client_token"), JsonConverter(typeof(StringOnlyConverter))] string? ClientToken,
    [property: JsonPropertyName("lease_duration"), JsonConverter(typeof(IntegerOnlyConverter))] int? LeaseDuration);

/// <summary>Source-generated metadata for the typed answers and the login body.</summary>
/// <remarks>
/// Names match without regard to case and numbers are read only as numbers, as the web-style
/// options the answers were read with as a <c>JsonNode</c> tree did. The payload of a secret is
/// still a tree, read with the same options, so its keys match as they did.
/// </remarks>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(MetadataAnswer))]
[JsonSerializable(typeof(SecretAnswer))]
[JsonSerializable(typeof(LoginAnswer))]
[JsonSerializable(typeof(Dictionary<string, string?>))]
internal sealed partial class VaultJson : JsonSerializerContext;
