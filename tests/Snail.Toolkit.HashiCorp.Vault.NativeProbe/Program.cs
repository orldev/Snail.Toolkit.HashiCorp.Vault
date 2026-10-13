using System.Diagnostics;
using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;
using Snail.Toolkit.HashiCorp.Vault;
using Snail.Toolkit.HashiCorp.Vault.Http;

var options = new VaultOptions
{
    Address = "http://vault.local:8200/",
    RoleId = "role",
    SecretId = "secret",
    MountPath = "secret",
    ExpandJsonValues = true,
    ReloadCheckIntervalSeconds = 1,
    Secrets = [new VaultSecret("mongo"), new VaultSecret("shared", ConfigurationPrefix: "")],
};

var vault = new MemoryVault();
using var reader = new VaultHttpClient(options, new HttpClient(vault) { BaseAddress = new Uri(options.Address) });
using var loaded = (ConfigurationRoot)new ConfigurationBuilder()
    .Add(new VaultConfigurationSource(options, reader))
    .Build();

var isLoaded = loaded["mongo:Connection"] == "mongodb://db"
    && loaded["Seq:Url"] == "http://seq"
    && loaded["Seq:Ports:0"] == "5341"
    && vault.Credentials == """{"role_id":"role","secret_id":"secret"}"""
    && vault.Token == "t-1";

vault.Rotate();

var reloading = Stopwatch.StartNew();
while (loaded["mongo:Connection"] != "mongodb://db2" && reloading.Elapsed < TimeSpan.FromSeconds(10))
{
    await Task.Delay(50);
}

var isReloaded = loaded["mongo:Connection"] == "mongodb://db2";

var settings = new ConfigurationBuilder()
    .AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Vault:Address"] = "http://127.0.0.1:1",
        ["Vault:Token"] = "root",
        ["Vault:MountPath"] = "secret",
        ["Vault:Optional"] = "true",
        ["Vault:LoadTimeoutSeconds"] = "1",
        ["Vault:ReconnectIntervalSeconds"] = "1",
        ["Vault:Secrets:0:Path"] = "mongo",
    });

var binding = Stopwatch.StartNew();
using var skipped = (ConfigurationRoot)settings.AddVault().Build();
var isBound = binding.Elapsed < TimeSpan.FromSeconds(10) && skipped["mongo:Connection"] is null;

Console.WriteLine($"loaded {isLoaded}, reloaded {isReloaded}, settings bound {isBound}");

return isLoaded && isReloaded && isBound ? 0 : 1;

/// <summary>A Vault answering from memory: an AppRole login, two KV v2 secrets and their metadata.</summary>
internal sealed class MemoryVault : HttpMessageHandler
{
    private volatile int _version = 1;

    public string? Credentials { get; private set; }

    public string? Token { get; private set; }

    /// <summary>Writes a new version of the mongo secret, as a rotation does.</summary>
    public void Rotate() => _version = 2;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;

        if (path == "/v1/auth/approle/login")
        {
            Credentials = await request.Content!.ReadAsStringAsync(cancellationToken);

            return Answer(HttpStatusCode.OK, """{"auth": {"client_token": "t-1", "lease_duration": 3600}}""");
        }

        Token = request.Headers.GetValues("X-Vault-Token").Single();

        var version = _version;
        var body = path switch
        {
            "/v1/secret/data/mongo" =>
                $$"""{"data": {"data": {"Connection": "mongodb://db{{(version == 1 ? "" : "2")}}"}, "metadata": {"version": {{version}} } } }""",
            "/v1/secret/metadata/mongo" => $$"""{"data": {"current_version": {{version}} } }""",
            "/v1/secret/data/shared" =>
                """{"data": {"data": {"Seq": "{\"Url\":\"http://seq\",\"Ports\":[5341]}"}, "metadata": {"version": 1}}}""",
            "/v1/secret/metadata/shared" => """{"data": {"current_version": 1}}""",
            _ => null
        };

        return body is null ? Answer(HttpStatusCode.NotFound, """{"errors": []}""") : Answer(HttpStatusCode.OK, body);
    }

    private static HttpResponseMessage Answer(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
}
