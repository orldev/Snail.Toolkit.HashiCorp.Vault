using System.Net;
using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault.Tests.Chaos;

/// <summary>What the load waits out and what it refuses at once: a refused status against an absent server.</summary>
public class FailureClassificationTests
{
    private static VaultOptions Options(params VaultSecret[] secrets) => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        Token = "root",
        Logger = (_, _) => { },
        Secrets = secrets,
    };

    private static VaultHttpClient Client(VaultOptions options, HttpMessageHandler handler) =>
        new(options, new HttpClient(handler) { BaseAddress = new Uri("http://vault.local:8200/") });

    /// <summary>
    /// A static token Vault refuses is a wrong setting, not a server away: the load fails on the first answer
    /// and names the refusal, instead of retrying for the whole budget and blaming LoadTimeoutSeconds.
    /// </summary>
    [Fact]
    public void Load_StaticTokenRefused_FailsAtOnceAndNotAsATimeout()
    {
        var handler = new RecordingHandler(HttpStatusCode.Forbidden, """{"errors": ["permission denied"]}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.Token = "wrong";
        options.LoadTimeoutSeconds = 2;
        options.ReconnectIntervalSeconds = 1;
        using var reader = Client(options, handler);
        using var provider = new VaultConfigurationProvider(options, reader);

        var error = Record.Exception(provider.Load);

        Assert.IsType<HttpRequestException>(error, exactMatch: false);
        Assert.Single(handler.Requests);
    }

    /// <summary>A refused token is the configuration's mistake, which Optional is not allowed to hide.</summary>
    [Fact]
    public void Load_StaticTokenRefusedOnAnOptionalSource_StillFails()
    {
        var handler = new RecordingHandler(HttpStatusCode.Forbidden, """{"errors": ["permission denied"]}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.Optional = true;
        using var reader = Client(options, handler);
        using var provider = new VaultConfigurationProvider(options, reader);

        Assert.IsType<HttpRequestException>(Record.Exception(provider.Load), exactMatch: false);
    }

    /// <summary>A sealed or standing-by Vault answers 503 or 429: the server is there and will be back, so the load waits.</summary>
    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.BadGateway)]
    public void Load_ServerUnavailableStatus_IsRetriedWithinTheBudget(HttpStatusCode status)
    {
        var handler = new RecordingHandler(status, """{"errors": ["Vault is sealed"]}""");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.LoadTimeoutSeconds = 3;
        options.ReconnectIntervalSeconds = 1;
        using var reader = Client(options, handler);
        using var provider = new VaultConfigurationProvider(options, reader);

        Assert.IsType<TimeoutException>(Record.Exception(provider.Load));
        Assert.True(handler.Requests.Count > 1, $"{handler.Requests.Count} request(s) within a budget of two retries");
    }

    /// <summary>
    /// A proxy in front of Vault answers 200 with an HTML page while Vault restarts behind it. The body is not
    /// JSON, which is the same outage as a 502 from the same proxy, and is waited out within the budget.
    /// </summary>
    [Fact]
    public void Load_HtmlAnswerFromAProxy_IsRetriedLikeAnyOtherServerFault()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK, "<html>maintenance</html>");
        var options = Options(new VaultSecret(Path: "mongo"));
        options.LoadTimeoutSeconds = 3;
        options.ReconnectIntervalSeconds = 1;
        using var reader = Client(options, handler);
        using var provider = new VaultConfigurationProvider(options, reader);

        Record.Exception(provider.Load);

        Assert.True(handler.Requests.Count > 1, $"{handler.Requests.Count} request(s) within a budget of two retries");
    }
}
