using System.Net;
using System.Text;
using System.Text.Json;
using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault.Tests;

public class VaultHttpClientTests
{
    private const string SecretBody = """{"data": {"data": {"Connection": "a"}, "metadata": {"version": 7}}}""";

    private static VaultOptions Options() => new()
    {
        Address = "http://vault.local:8200",
        MountPath = "secret",
        Token = "root",
    };

    private static VaultHttpClient Client(HttpMessageHandler handler, VaultOptions? options = null) =>
        new(options ?? Options(), new HttpClient(handler) { BaseAddress = new Uri("http://vault.local:8200/") });

    private static VaultOptions AppRole()
    {
        var options = Options();
        options.Token = null;
        options.RoleId = "role";
        options.SecretId = "secret";

        return options;
    }

    [Fact]
    public void Client_BuildsATransportThatRecyclesItsConnections()
    {
        var options = Options();
        SocketsHttpHandler? transport = null;
        options.ConfigureTransport = handler => transport = handler;

        using var client = new VaultHttpClient(options);

        Assert.NotNull(transport);
        Assert.Equal(TimeSpan.FromSeconds(120), transport.PooledConnectionLifetime);
    }

    [Fact]
    public async Task ReadSecret_ReturnsThePayloadAndItsVersion()
    {
        using var client = Client(new RecordingHandler(body: SecretBody));

        var secret = await client.ReadSecretAsync(new VaultSecret(Path: "mongo"));

        Assert.Equal("a", secret.Data["Connection"]!.ToString());
        Assert.Equal(7, secret.Version);
    }

    [Fact]
    public async Task ReadSecret_ResponseWithoutMetadataLeavesTheVersionUnknown()
    {
        using var client = Client(new RecordingHandler(body: """{"data": {"data": {"Connection": "a"}}}"""));

        var secret = await client.ReadSecretAsync(new VaultSecret(Path: "mongo"));

        Assert.Null(secret.Version);
    }

    [Fact]
    public async Task ReadSecret_PathSegmentsAreEscapedAndSeparatorsSurvive()
    {
        var handler = new RecordingHandler(body: SecretBody);
        using var client = Client(handler);

        await client.ReadSecretAsync(new VaultSecret(Path: "team a/mongo?version=1"));

        var request = Assert.Single(handler.Requests);
        Assert.Equal("/v1/secret/data/team%20a/mongo%3Fversion%3D1", request.AbsolutePath);
        Assert.Equal(string.Empty, request.Query);
    }

    [Fact]
    public async Task ReadSecret_PinnedVersionTravelsAsAQuery()
    {
        var handler = new RecordingHandler(body: SecretBody);
        using var client = Client(handler);

        await client.ReadSecretAsync(new VaultSecret(Path: "mongo", Version: 3));

        Assert.Equal("?version=3", Assert.Single(handler.Requests).Query);
    }

    [Fact]
    public async Task ReadSecret_PathWalkingOutsideTheMountIsRejected()
    {
        using var client = Client(new RecordingHandler(body: SecretBody));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ReadSecretAsync(new VaultSecret(Path: "../other/mongo")));
    }

    [Fact]
    public async Task ReadSecret_MissingSecretBecomesSecretNotFound()
    {
        using var client = Client(new RecordingHandler(HttpStatusCode.NotFound, """{"errors": []}"""));

        var error = await Assert.ThrowsAsync<SecretNotFoundException>(
            () => client.ReadSecretAsync(new VaultSecret(Path: "mongo")));

        Assert.Equal("mongo", error.Path);
        Assert.NotNull(error.InnerException);
    }

    [Fact]
    public async Task ReadSecret_SecretWithoutAMountPathIsRejected()
    {
        var options = Options();
        options.MountPath = null;
        using var client = Client(new RecordingHandler(body: SecretBody), options);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ReadSecretAsync(new VaultSecret(Path: "mongo")));
    }

    [Fact]
    public async Task Login_LeaseStillValidIsReusedAcrossRequests()
    {
        var handler = new LeasedVaultHandler(leaseSeconds: 3600);
        using var client = Client(handler, AppRole());

        await client.ReadSecretAsync(new VaultSecret(Path: "first"));
        await client.ReadSecretAsync(new VaultSecret(Path: "second"));

        Assert.Equal(1, handler.Logins);
    }

    [Fact]
    public async Task Login_ExpiringLeaseIsReplacedBeforeVaultRefusesIt()
    {
        var handler = new LeasedVaultHandler(leaseSeconds: 1);
        using var client = Client(handler, AppRole());

        await client.ReadSecretAsync(new VaultSecret(Path: "mongo"));
        await Task.Delay(TimeSpan.FromSeconds(1.2));
        await client.ReadSecretAsync(new VaultSecret(Path: "mongo"));

        Assert.Equal(2, handler.Logins);
    }

    [Fact]
    public async Task Login_RequestsRefusedTogetherShareOneRenewal()
    {
        var handler = new AppRoleHandler(refusalsExpected: 2);
        using var client = Client(handler, AppRole());

        await Task.WhenAll(
            client.ReadSecretAsync(new VaultSecret(Path: "first")),
            client.ReadSecretAsync(new VaultSecret(Path: "second")));

        Assert.Equal(2, handler.Logins);
    }

    [Fact]
    public async Task Login_UnmountedAppRoleIsNotReportedAsAMissingSecret()
    {
        using var client = Client(new UnmountedAppRoleHandler(), AppRole());

        var error = await Record.ExceptionAsync(
            () => client.ReadSecretAsync(new VaultSecret(Path: "mongo")));

        Assert.NotNull(error);
        Assert.IsNotType<SecretNotFoundException>(error);
    }

    [Fact]
    public async Task ReadSecretVersion_ReadsTheCurrentVersionFromMetadata()
    {
        var handler = new RecordingHandler(body: """{"data": {"current_version": 4}}""");
        using var client = Client(handler);

        var version = await client.ReadSecretVersionAsync(new VaultSecret(Path: "mongo"));

        Assert.Equal(4, version);
        Assert.Equal("/v1/secret/metadata/mongo", Assert.Single(handler.Requests).AbsolutePath);
    }

    /// <summary>The metadata answer read as it was when it was a tree: names in any case, gaps as no version.</summary>
    [Theory]
    [InlineData("""{"data": {"current_version": 4, "versions": {"4": {"destroyed": false}}}}""", 4)]
    [InlineData("""{"Data": {"Current_Version": 5}}""", 5)]
    [InlineData("""{"data": {"current_version": null}}""", null)]
    [InlineData("""{"data": {}}""", null)]
    [InlineData("""{"data": null}""", null)]
    [InlineData("""{}""", null)]
    [InlineData("", null)]
    public async Task ReadSecretVersion_AnyShapeOfAnswer_ReadsTheVersionOrNone(string body, int? expected)
    {
        using var client = Client(new RecordingHandler(body: body));

        var version = await client.ReadSecretVersionAsync(new VaultSecret(Path: "mongo"));

        Assert.Equal(expected, version);
    }

    /// <summary>A version that is not a number is a failure, which the reload turns into a full read.</summary>
    [Theory]
    [InlineData("""{"data": {"current_version": "4"}}""")]
    [InlineData("""{"data": {"current_version": 4.5}}""")]
    [InlineData("""{"data": []}""")]
    public async Task ReadSecretVersion_VersionThatIsNotAnInteger_Fails(string body)
    {
        using var client = Client(new RecordingHandler(body: body));

        await Assert.ThrowsAnyAsync<Exception>(() => client.ReadSecretVersionAsync(new VaultSecret(Path: "mongo")));
    }

    /// <summary>
    /// An answer of the wrong shape is a configuration error, as it was when the answers were read as a
    /// tree: InvalidOperationException, which Optional does not hide, never the JsonException of a typed read.
    /// </summary>
    [Theory]
    [InlineData("""{"data": 5}""")]
    [InlineData("""{"data": "text"}""")]
    [InlineData("""{"data": []}""")]
    [InlineData("""[]""")]
    [InlineData("\"text\"")]
    [InlineData("""{"data": {"data": []}}""")]
    [InlineData("""{"data": {"data": "text"}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}, "metadata": 5}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}, "metadata": []}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}, "metadata": {"version": "7"}}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}, "metadata": {"version": 7.5}}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}, "metadata": {"version": 4294967296}}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}, "metadata": {"version": true}}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}, "metadata": {"version": {}}}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}, "metadata": {"version": []}}}""")]
    public async Task ReadSecret_AnswerOfTheWrongShape_FailsAsAConfigurationError(string body)
    {
        using var client = Client(new RecordingHandler(body: body));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ReadSecretAsync(new VaultSecret(Path: "mongo")));
    }

    /// <summary>The login answer of the wrong shape fails as the secret answer does.</summary>
    [Theory]
    [InlineData("""{"auth": 5}""")]
    [InlineData("""{"auth": "text"}""")]
    [InlineData("""{"auth": []}""")]
    [InlineData("""[]""")]
    [InlineData("""{"auth": {"client_token": 5}}""")]
    [InlineData("""{"auth": {"client_token": true}}""")]
    [InlineData("""{"auth": {"client_token": {}}}""")]
    [InlineData("""{"auth": {"client_token": []}}""")]
    [InlineData("""{"auth": {"client_token": "t", "lease_duration": "60"}}""")]
    [InlineData("""{"auth": {"client_token": "t", "lease_duration": 60.5}}""")]
    [InlineData("""{"auth": {"client_token": "t", "lease_duration": true}}""")]
    [InlineData("""{"auth": {"client_token": "t", "lease_duration": {}}}""")]
    public async Task Login_AnswerOfTheWrongShape_FailsAsAConfigurationError(string login)
    {
        using var client = Client(new LoginAnswerHandler(login), AppRole());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ReadSecretAsync(new VaultSecret(Path: "mongo")));
    }

    /// <summary>A body that is not JSON at all fails with JsonException, as it always did.</summary>
    [Theory]
    [InlineData("<html>")]
    [InlineData("""{"data": {"data": {"a": "1"}}""")]
    [InlineData("""{"data": {"data": {"a": "1"}}} trailing""")]
    public async Task ReadSecret_BodyThatIsNotJson_FailsWithJsonException(string body)
    {
        using var client = Client(new RecordingHandler(body: body));

        await Assert.ThrowsAsync<JsonException>(() => client.ReadSecretAsync(new VaultSecret(Path: "mongo")));
    }

    /// <summary>The login answer that is not JSON fails as the secret answer does.</summary>
    [Theory]
    [InlineData("<html>")]
    [InlineData("""{"auth": {"client_token": "t"}""")]
    public async Task Login_BodyThatIsNotJson_FailsWithJsonException(string login)
    {
        using var client = Client(new LoginAnswerHandler(login), AppRole());

        await Assert.ThrowsAsync<JsonException>(() => client.ReadSecretAsync(new VaultSecret(Path: "mongo")));
    }

    /// <summary>Names match in any case, and fields the read does not need are not judged.</summary>
    [Theory]
    [InlineData("""{"Data": {"DATA": {"Connection": "a"}, "Metadata": {"VERSION": 7}}}""", 7)]
    [InlineData("""{"data": {"data": {"Connection": "a"}, "metadata": {"version": null}}, "auth": 5}""", null)]
    [InlineData("""{"data": {"data": {"Connection": "a"}, "metadata": null, "versions": []}}""", null)]
    public async Task ReadSecret_AnswerInAnyCaseWithFieldsItSkips_ReadsThePayload(string body, int? version)
    {
        using var client = Client(new RecordingHandler(body: body));

        var secret = await client.ReadSecretAsync(new VaultSecret(Path: "mongo"));

        Assert.Equal("a", secret.Data["connection"]!.ToString());
        Assert.Equal(version, secret.Version);
    }

    /// <summary>The login answer in any case, with a lease that is not stated.</summary>
    [Theory]
    [InlineData("""{"AUTH": {"Client_Token": "t-9", "Lease_Duration": 3600}}""")]
    [InlineData("""{"auth": {"client_token": "t-9", "lease_duration": null}, "data": 5}""")]
    public async Task Login_AnswerInAnyCase_SendsTheGrantedToken(string login)
    {
        var handler = new LoginAnswerHandler(login);
        using var client = Client(handler, AppRole());

        await client.ReadSecretAsync(new VaultSecret(Path: "mongo"));

        Assert.Equal("t-9", handler.Token);
        Assert.Equal("""{"role_id":"role","secret_id":"secret"}""", handler.Credentials);
    }

    /// <summary>A Vault whose AppRole login answers with the given body and whose secrets are well formed.</summary>
    private sealed class LoginAnswerHandler(string login) : HttpMessageHandler
    {
        public string? Token { get; private set; }

        public string? Credentials { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var isLogin = request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal);

            if (isLogin)
                Credentials = await request.Content!.ReadAsStringAsync(cancellationToken);
            else
                Token = request.Headers.GetValues("X-Vault-Token").Single();

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(isLogin ? login : SecretBody, Encoding.UTF8, "application/json"),
            };
        }
    }

    /// <summary>A Vault where the AppRole backend is not mounted, so the login itself answers 404.</summary>
    private sealed class UnmountedAppRoleHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(
                request.RequestUri!.AbsolutePath.EndsWith("/login", StringComparison.Ordinal)
                    ? HttpStatusCode.NotFound
                    : HttpStatusCode.OK)
            {
                Content = new StringContent(SecretBody, Encoding.UTF8, "application/json"),
            });
    }
}
