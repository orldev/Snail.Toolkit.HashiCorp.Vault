using System.Net;
using System.Text;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

/// <summary>Answers every request with a canned response and keeps the requests for inspection.</summary>
internal sealed class RecordingHandler(HttpStatusCode status = HttpStatusCode.OK, string body = "{}")
    : HttpMessageHandler
{
    public List<Uri> Requests { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request.RequestUri!);

        return Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
    }
}
