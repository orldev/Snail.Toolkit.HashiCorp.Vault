using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;

namespace Snail.Toolkit.HashiCorp.Vault.Tests.Integration;

/// <summary>
/// One Vault dev server for the whole integration suite: KV v2 at the <c>secret</c> mount,
/// a root token, and an AppRole with read access to it.
/// </summary>
public sealed class VaultContainerFixture : IAsyncLifetime
{
    public const string RootToken = "root";

    private readonly IContainer _container = new ContainerBuilder("hashicorp/vault:2.0.4")
        .WithPortBinding(8200, true)
        .WithEnvironment("VAULT_DEV_ROOT_TOKEN_ID", RootToken)
        .WithEnvironment("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
        .WithWaitStrategy(Wait.ForUnixContainer()
            .UntilHttpRequestIsSucceeded(request => request.ForPort(8200).ForPath("/v1/sys/health")))
        .Build();

    public string Address => $"http://{_container.Hostname}:{_container.GetMappedPublicPort(8200)}";

    public string RoleId { get; private set; } = "";

    public string SecretId { get; private set; } = "";

    public async Task InitializeAsync()
    {
        await _container.StartAsync();

        await ExecAsync("vault auth enable approle");
        await ExecAsync("""echo 'path "secret/*" { capabilities = ["read", "list"] }' | vault policy write reader -""");
        await ExecAsync("vault write auth/approle/role/reader token_policies=reader token_ttl=1h");

        RoleId = (await ExecAsync("vault read -field=role_id auth/approle/role/reader/role-id")).Trim();
        SecretId = (await ExecAsync("vault write -f -field=secret_id auth/approle/role/reader/secret-id")).Trim();
    }

    public Task DisposeAsync() => _container.DisposeAsync().AsTask();

    /// <summary>Runs a Vault CLI command inside the container under the root token.</summary>
    public async Task<string> ExecAsync(string command)
    {
        var result = await _container.ExecAsync(
            ["/bin/sh", "-c", $"export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN={RootToken}; {command}"]);

        if (result.ExitCode != 0)
            throw new InvalidOperationException($"'{command}' failed: {result.Stderr}");

        return result.Stdout;
    }
}
