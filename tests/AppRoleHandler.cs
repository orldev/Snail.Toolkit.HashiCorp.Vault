using System.Net;
using System.Text;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

/// <summary>
/// A Vault that issues a fresh token per login and refuses the first one it ever issued, holding every
/// refusal until <paramref name="refusalsExpected"/> requests are waiting so they are refused together.
/// </summary>
internal sealed class AppRoleHandler(int refusalsExpected) : HttpMessageHandler
{
    private readonly TaskCompletionSource _refusedTogether = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _logins;
    private int _refusals;

    public int Logins => Volatile.Read(ref _logins);

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal))
        {
            var issued = $"t{Interlocked.Increment(ref _logins)}";

            return Json(HttpStatusCode.OK, $$$"""{"auth": {"client_token": "{{{issued}}}"}}""");
        }

        if (request.Headers.GetValues("X-Vault-Token").First() != "t1")
            return Json(HttpStatusCode.OK,
                """{"data": {"data": {"Connection": "a"}, "metadata": {"version": 1}}}""");

        if (Interlocked.Increment(ref _refusals) == refusalsExpected)
            _refusedTogether.TrySetResult();

        await _refusedTogether.Task.WaitAsync(cancellationToken);

        return Json(HttpStatusCode.Forbidden, """{"errors": ["permission denied"]}""");
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
