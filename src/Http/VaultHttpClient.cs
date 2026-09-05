using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using Snail.Toolkit.HttpBuilder.Extensions;

namespace Snail.Toolkit.HashiCorp.Vault.Http;

/// <summary>The thin HTTP layer over the Vault API: AppRole or token authentication and KV v2 reads.</summary>
public sealed class VaultHttpClient : TypedHttpClientBase, IVaultReader, IDisposable
{
    private const string TokenHeader = "X-Vault-Token";

    private readonly VaultOptions _options;
    private readonly HttpClient? _ownedClient;
    private readonly SemaphoreSlim _login = new(1, 1);
    private Lease? _lease;

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
            () => Get($"v1/{mountPath}/data/{path}")
                .Query("version", secret.Version?.ToString(CultureInfo.InvariantCulture)),
            secret.Path!, cancellationToken).ConfigureAwait(false);

        var data = response?["data"];
        if (data?["data"] is not JsonObject payload)
            throw new InvalidOperationException($"Vault: the response for the secret '{path}' carries no data.");

        return new Kv2Secret(payload, data["metadata"]?["version"]?.GetValue<int>());
    }

    /// <inheritdoc/>
    public async Task<int?> ReadSecretVersionAsync(VaultSecret secret, CancellationToken cancellationToken = default)
    {
        var (mountPath, path) = Locate(secret);
        var response = await SendAuthorizedAsync(
            () => Get($"v1/{mountPath}/metadata/{path}"),
            secret.Path!, cancellationToken).ConfigureAwait(false);

        return response?["data"]?["current_version"]?.GetValue<int>();
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

        return (Escape(mountPath), Escape(secret.Path));
    }

    /// <summary>Escapes a path segment by segment, so the separators survive and nothing else can alter the request.</summary>
    /// <remarks>
    /// An unescaped path lets a '?' append a query that overrides the pinned version and a '..' reach a
    /// different mount, so the request would not be the one the configuration described.
    /// </remarks>
    private static string Escape(string path)
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length == 0)
            throw new InvalidOperationException($"Vault: the path '{path}' names nothing.");

        if (Array.Exists(segments, segment => segment is "." or ".."))
            throw new InvalidOperationException($"Vault: the path '{path}' walks outside its mount.");

        return string.Join('/', segments.Select(Uri.EscapeDataString));
    }

    private async Task<JsonNode?> SendAuthorizedAsync(
        Func<IHttpRequestBuilder> request, string path, CancellationToken cancellationToken)
    {
        var token = await GetTokenAsync(stale: null, cancellationToken).ConfigureAwait(false);

        try
        {
            return await ReadAsync(request, token, path, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpBuilderException ex) when (
            ex.StatusCode == HttpStatusCode.Forbidden && string.IsNullOrEmpty(_options.Token))
        {
            var renewed = await GetTokenAsync(token, cancellationToken).ConfigureAwait(false);

            return await ReadAsync(request, renewed, path, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Sends one authorised read, reporting a secret the server does not have as such.</summary>
    /// <remarks>
    /// The mapping covers the read alone. A login that answers 404 — an AppRole backend that is not
    /// mounted — would otherwise be reported as a missing secret and hide the real fault.
    /// </remarks>
    private async Task<JsonNode?> ReadAsync(
        Func<IHttpRequestBuilder> request, string token, string path, CancellationToken cancellationToken)
    {
        try
        {
            return await request().Header(TokenHeader, token)
                .SendAsync<JsonNode>(cancellationToken).ConfigureAwait(false);
        }
        catch (HttpBuilderException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            throw new SecretNotFoundException(path, ex);
        }
    }

    /// <summary>Returns a usable token, logging in when the held one has run out or is the <paramref name="stale"/> one that was refused.</summary>
    /// <remarks>
    /// Requests that were refused together must not each start a login: an AppRole with a limited
    /// secret_id_num_uses would be spent by the duplicates and the role would lock out.
    /// </remarks>
    private async Task<string> GetTokenAsync(string? stale, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_options.Token))
            return _options.Token;

        if (stale is null && _lease is { } current && current.Expires > DateTimeOffset.UtcNow)
            return current.Token;

        await _login.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var lease = _lease;

            if (lease is null || lease.Expires <= DateTimeOffset.UtcNow ||
                string.Equals(lease.Token, stale, StringComparison.Ordinal))
                lease = _lease = await LoginAsync(cancellationToken).ConfigureAwait(false);

            return lease.Token;
        }
        finally
        {
            _login.Release();
        }
    }

    private async Task<Lease> LoginAsync(CancellationToken cancellationToken)
    {
        var response = await Post("v1/auth/approle/login")
            .AsJson(new Dictionary<string, string?>
            {
                ["role_id"] = _options.RoleId,
                ["secret_id"] = _options.SecretId,
            })
            .SendAsync<JsonNode>(cancellationToken).ConfigureAwait(false);

        var auth = response?["auth"];
        var token = auth?["client_token"]?.GetValue<string>()
            ?? throw new InvalidOperationException("Vault: the AppRole login response carries no client token.");

        return new Lease(token, Expiry(auth?["lease_duration"]?.GetValue<int>() ?? 0));
    }

    /// <summary>When to stop using a token — a little before Vault stops accepting it.</summary>
    /// <remarks>
    /// Waiting for the refusal costs a failed request every time the lease runs out, and with a reload
    /// interval longer than the lease that is every single cycle. A tenth of the lease, at most a minute,
    /// is taken off so the login happens first. A lease of zero is a token that does not expire.
    /// </remarks>
    private static DateTimeOffset Expiry(int leaseSeconds) =>
        leaseSeconds <= 0
            ? DateTimeOffset.MaxValue
            : DateTimeOffset.UtcNow.AddSeconds(leaseSeconds - Math.Min(leaseSeconds / 10.0, 60));

    /// <summary>A token and the moment it stops being usable, kept together so they cannot disagree.</summary>
    private sealed record Lease(string Token, DateTimeOffset Expires);

    private static HttpClient CreateClient(VaultOptions options)
    {
        if (string.IsNullOrEmpty(options.Address))
            throw new InvalidOperationException("Vault: Address is not configured.");

        var handler = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromSeconds(options.ConnectionLifetimeSeconds),
        };

        options.ConfigureTransport?.Invoke(handler);

        var address = options.Address.EndsWith('/') ? options.Address : $"{options.Address}/";
        return new HttpClient(handler) { BaseAddress = new Uri(address) };
    }
}
