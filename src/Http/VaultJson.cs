using System.Text.Json.Serialization;

namespace Snail.Toolkit.HashiCorp.Vault.Http;

/// <summary>The part of a KV v2 metadata answer the version probe reads.</summary>
/// <param name="Metadata">The metadata, under <c>data</c>.</param>
internal sealed record MetadataAnswer([property: JsonPropertyName("data")] SecretMetadata? Metadata);

/// <summary>The current version of a secret, the one field of its metadata the probe needs.</summary>
/// <param name="CurrentVersion">The version a read without a pinned version returns.</param>
/// <remarks>The version history beside it is skipped, not built into a tree.</remarks>
internal sealed record SecretMetadata([property: JsonPropertyName("current_version")] int? CurrentVersion);

/// <summary>Source-generated metadata for the typed answers.</summary>
/// <remarks>
/// Names match without regard to case and numbers are read only as numbers, as the web-style
/// options the answers were read with as a <c>JsonNode</c> tree did.
/// </remarks>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(MetadataAnswer))]
internal sealed partial class VaultJson : JsonSerializerContext;
