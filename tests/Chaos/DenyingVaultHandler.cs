using System.Net;
using System.Text;

namespace Snail.Toolkit.HashiCorp.Vault.Tests.Chaos;

/// <summary>
/// A Vault whose policy denies what the test says: every AppRole login grants a fresh token, and a denied
/// endpoint answers 403 whatever token it is shown, as a policy without the capability does.
/// </summary>
internal sealed class DenyingVaultHandler(bool deniesData = false, bool deniesMetadata = false) : HttpMessageHandler
{
    private const string Secret = """{"data": {"data": {"Connection": "a"}, "metadata": {"version": 1}}}""";

    private const string Metadata = """{"data": {"current_version": 1}}""";

    private const string Denied = """{"errors": ["1 error occurred:\n\t* permission denied\n\n"]}""";

    private int _logins;

    public int Logins => Volatile.Read(ref _logins);

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;

        if (path.EndsWith("/login", StringComparison.Ordinal))
        {
            var issued = $"t{Interlocked.Increment(ref _logins)}";

            return Task.FromResult(Json(HttpStatusCode.OK,
                $$$"""{"auth": {"client_token": "{{{issued}}}", "lease_duration": 3600}}"""));
        }

        if (path.Contains("/metadata/", StringComparison.Ordinal))
            return Task.FromResult(deniesMetadata ? Json(HttpStatusCode.Forbidden, Denied) : Json(HttpStatusCode.OK, Metadata));

        return Task.FromResult(deniesData ? Json(HttpStatusCode.Forbidden, Denied) : Json(HttpStatusCode.OK, Secret));
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
