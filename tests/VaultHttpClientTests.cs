using System.Net;
using System.Text;
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
