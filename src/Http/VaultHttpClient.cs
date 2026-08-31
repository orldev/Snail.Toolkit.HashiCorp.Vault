using System.Net;
using System.Text.Json.Nodes;
using Snail.Toolkit.HttpBuilder.Extensions;
using HttpBuilderBase = Snail.Toolkit.HttpBuilder.Extensions.HttpBuilder;

namespace Snail.Toolkit.HashiCorp.Vault.Http;

/// <summary>The thin HTTP layer over the Vault API: AppRole or token authentication and KV v2 reads.</summary>
public sealed class VaultHttpClient : HttpBuilderBase, IVaultReader, IDisposable
{
    private const string TokenHeader = "X-Vault-Token";

    private readonly VaultOptions _options;
    private readonly HttpClient? _ownedClient;
    private readonly SemaphoreSlim _login = new(1, 1);
    private string? _token;

    /// <summary>Creates a client that owns its connection to <see cref="VaultOptions.Address"/>.</summary>
    public VaultHttpClient(VaultOptions options) : this(options, CreateClient(options), ownsClient: true) { }

    /// <summary>Creates a client over an externally managed connection.</summary>
    public VaultHttpClient(VaultOptions options, HttpClient httpClient) : this(options, httpClient, ownsClient: false) { }

    private VaultHttpClient(VaultOptions options, HttpClient httpClient, bool ownsClient) : base(httpClient)
    {
        _options = options;
        _ownedClient = ownsClient ? httpClient : null;
    }

    /// <inheritdoc/>
    public async Task<Kv2Secret> ReadSecretAsync(VaultSecret secret, CancellationToken cancellationToken = default)
    {
        var (mountPath, path) = Locate(secret);
        var response = await SendAuthorizedAsync(
            () => Get($"v1/{mountPath}/data/{path}").Query("version", secret.Version?.ToString()),
            path, cancellationToken).ConfigureAwait(false);

        var data = response?["data"];
        if (data?["data"] is not JsonObject payload)
            throw new InvalidOperationException($"Vault: the response for the secret '{path}' carries no data.");

        var version = data["metadata"]?["version"]?.GetValue<int>() ?? 0;
        return new Kv2Secret(payload, version);
    }

    /// <inheritdoc/>
    public async Task<int> ReadSecretVersionAsync(VaultSecret secret, CancellationToken cancellationToken = default)
    {
        var (mountPath, path) = Locate(secret);
        var response = await SendAuthorizedAsync(
            () => Get($"v1/{mountPath}/metadata/{path}"),
            path, cancellationToken).ConfigureAwait(false);

        return response?["data"]?["current_version"]?.GetValue<int>() ?? 0;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _login.Dispose();
        _ownedClient?.Dispose();
    }

    private (string MountPath, string Path) Locate(VaultSecret secret)
    {
        if (string.IsNullOrEmpty(secret.Path))
            throw new InvalidOperationException("Vault: a secret has no Path.");

        var mountPath = string.IsNullOrEmpty(secret.MountPath) ? _options.MountPath : secret.MountPath;
        if (string.IsNullOrEmpty(mountPath))
            throw new InvalidOperationException(
                $"Vault: no mount path for the secret '{secret.Path}' — set Vault:MountPath or the secret's MountPath.");

        return (mountPath.Trim('/'), secret.Path.Trim('/'));
    }

    private async Task<JsonNode?> SendAuthorizedAsync(
        Func<IHttpRequestBuilder> request, string path, CancellationToken cancellationToken)
    {
        try
        {
            var token = await GetTokenAsync(refresh: false, cancellationToken).ConfigureAwait(false);
            try
            {
                return await request().Header(TokenHeader, token)
                    .SendAsync<JsonNode>(cancellationToken).ConfigureAwait(false);
            }
            catch (HttpBuilderException ex) when (
                ex.StatusCode == HttpStatusCode.Forbidden && string.IsNullOrEmpty(_options.Token))
            {
                token = await GetTokenAsync(refresh: true, cancellationToken).ConfigureAwait(false);
                return await request().Header(TokenHeader, token)
                    .SendAsync<JsonNode>(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (HttpBuilderException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            throw new SecretNotFoundException(path);
        }
    }

    private async Task<string> GetTokenAsync(bool refresh, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_options.Token))
            return _options.Token;

        if (!refresh && _token is { } token)
            return token;

        await _login.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (refresh || _token is null)
                _token = await LoginAsync(cancellationToken).ConfigureAwait(false);

            return _token;
        }
        finally
        {
            _login.Release();
        }
    }

    private async Task<string> LoginAsync(CancellationToken cancellationToken)
    {
        var response = await Post("v1/auth/approle/login")
            .AsJson(new Dictionary<string, string?>
            {
                ["role_id"] = _options.RoleId,
                ["secret_id"] = _options.SecretId,
            })
            .SendAsync<JsonNode>(cancellationToken).ConfigureAwait(false);

        return response?["auth"]?["client_token"]?.GetValue<string>()
            ?? throw new InvalidOperationException("Vault: the AppRole login response carries no client token.");
    }

    private static HttpClient CreateClient(VaultOptions options)
    {
        if (string.IsNullOrEmpty(options.Address))
            throw new InvalidOperationException("Vault: Address is not configured.");

        var address = options.Address.EndsWith('/') ? options.Address : $"{options.Address}/";
        return new HttpClient { BaseAddress = new Uri(address) };
    }
}
