using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Snail.Toolkit.HashiCorp.Vault.Benchmarks;

/// <summary>
/// Answers Vault's KV v2 data and metadata endpoints from memory, with the bodies a real server sends: twenty keys a
/// secret, one of them a JSON document, and a metadata answer carrying its seven versions. No socket.
/// </summary>
public sealed class CannedVault : HttpMessageHandler
{
    private static readonly byte[] MetadataBody = Metadata(7);

    private static readonly byte[] DataBody = Data(20, 7);

    public static VaultOptions Options() => new()
    {
        Address = "http://vault.local:8200",
        Token = "root",
        MountPath = "secret",
        Secrets = [.. Enumerable.Range(0, 5).Select(index => new VaultSecret($"apps/service-{index}"))]
    };

    public static HttpClient Client() => new(new CannedVault()) { BaseAddress = new Uri("http://vault.local:8200/") };

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.RequestUri!.AbsolutePath.Contains("/metadata/", StringComparison.Ordinal) ? MetadataBody : DataBody;
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content, RequestMessage = request });
    }

    private static byte[] Metadata(int version)
    {
        var versions = string.Join(",", Enumerable.Range(1, version)
            .Select(number => $"\"{number}\":{{\"created_time\":\"2026-10-0{(number % 9) + 1}T10:00:00.123456Z\",\"deletion_time\":\"\",\"destroyed\":false}}"));

        return Encoding.UTF8.GetBytes(
            "{\"request_id\":\"5b3f6c1e-8a2d-4c3b-9e1f-0a1b2c3d4e5f\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":{\"cas_required\":false,\"created_time\":\"2026-10-01T10:00:00.123456Z\",\"current_version\":"
            + version
            + ",\"custom_metadata\":null,\"delete_version_after\":\"0s\",\"max_versions\":0,\"oldest_version\":1,\"updated_time\":\"2026-10-10T10:00:00.123456Z\",\"versions\":{"
            + versions
            + "}},\"wrap_info\":null,\"warnings\":null,\"auth\":null,\"mount_type\":\"kv\"}");
    }

    private static byte[] Data(int keys, int version)
    {
        var pairs = string.Join(",", Enumerable.Range(0, keys)
            .Select(key => key == 0
                ? "\"Nested\":\"{\\\"Url\\\":\\\"https://example\\\",\\\"Retries\\\":[1,2,3]}\""
                : $"\"Setting{key}\":\"value-{key}-{new string('x', 24)}\""));

        return Encoding.UTF8.GetBytes(
            "{\"request_id\":\"5b3f6c1e-8a2d-4c3b-9e1f-0a1b2c3d4e5f\",\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,\"data\":{\"data\":{"
            + pairs
            + "},\"metadata\":{\"created_time\":\"2026-10-10T10:00:00.123456Z\",\"custom_metadata\":null,\"deletion_time\":\"\",\"destroyed\":false,\"version\":"
            + version
            + "}},\"wrap_info\":null,\"warnings\":null,\"auth\":null,\"mount_type\":\"kv\"}");
    }
}
