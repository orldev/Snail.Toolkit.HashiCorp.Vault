using System.Text.Json.Nodes;

namespace Snail.Toolkit.HashiCorp.Vault.Http;

/// <summary>One KV v2 secret: its data and the version it was read at, null when the server did not state one.</summary>
public sealed record Kv2Secret(JsonObject Data, int? Version);
