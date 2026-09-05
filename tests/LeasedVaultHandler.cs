using System.Net;
using System.Text;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

/// <summary>A Vault that issues a fresh token with the given lease on every login and answers every read.</summary>
internal sealed class LeasedVaultHandler(int leaseSeconds) : HttpMessageHandler
{
    private int _logins;

    public int Logins => Volatile.Read(ref _logins);

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal))
            return Task.FromResult(
                Json("""{"data": {"data": {"Connection": "a"}, "metadata": {"version": 1}}}"""));

        var issued = $"t{Interlocked.Increment(ref _logins)}";

        return Task.FromResult(Json(
            $$$"""{"auth": {"client_token": "{{{issued}}}", "lease_duration": {{{leaseSeconds}}} }}"""));
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
