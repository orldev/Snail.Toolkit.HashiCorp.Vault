using System.Text.Json.Nodes;

namespace Snail.Toolkit.HashiCorp.Vault.Http;

/// <summary>One KV v2 secret: its data and the version it was read at.</summary>
public sealed record Kv2Secret(JsonObject Data, int Version);
