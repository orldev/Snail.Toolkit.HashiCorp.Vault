using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
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
        var answer = await SendAuthorizedAsync(
            () => Get($"v1/{mountPath}/data/{path}")
                .Query("version", secret.Version?.ToString(CultureInfo.InvariantCulture)),
            VaultAnswers.Secret, secret.Path!, renewsOnRefusal: true, cancellationToken).ConfigureAwait(false);

        if (answer?.Content is not { Data: JsonObject payload } content)
            throw new InvalidOperationException($"Vault: the response for the secret '{path}' carries no data.");

        return new Kv2Secret(payload, content.Metadata?.Version);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Read into a record of the one field it needs, not into a tree of the whole answer with its
    /// version history: the probe runs for every secret on every reload interval. A refused probe buys no
    /// new token: metadata is the capability a read-only policy most often lacks, so its 403 is the policy's,
    /// and the full read the provider falls back to renews a token that really died.
    /// </remarks>
    public async Task<int?> ReadSecretVersionAsync(VaultSecret secret, CancellationToken cancellationToken = default)
    {
        var (mountPath, path) = Locate(secret);
        var response = await SendAuthorizedAsync(
            () => Get($"v1/{mountPath}/metadata/{path}"),
            VaultJson.Default.MetadataAnswer, secret.Path!, renewsOnRefusal: false, cancellationToken).ConfigureAwait(false);

        return response?.Metadata?.CurrentVersion;
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

        for (var index = 0; index < segments.Length; index++)
            segments[index] = Uri.EscapeDataString(segments[index]);

        return string.Join('/', segments);
    }

    private async Task<T?> SendAuthorizedAsync<T>(
        Func<IHttpRequestBuilder> request, JsonTypeInfo<T> answer, string path, bool renewsOnRefusal,
        CancellationToken cancellationToken)
    {
        var token = await GetTokenAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            return await ReadAsync(request, answer, token, path, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpBuilderException ex) when (
            renewsOnRefusal && ex.StatusCode == HttpStatusCode.Forbidden && string.IsNullOrEmpty(_options.Token))
        {
            var renewed = await RenewRefusedAsync(token, cancellationToken).ConfigureAwait(false);

            if (renewed is null)
                throw;

            return await ReadAsync(request, answer, renewed, path, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Sends one authorised read, reporting a secret the server does not have as such.</summary>
    /// <remarks>
    /// The mapping covers the read alone. A login that answers 404 — an AppRole backend that is not
    /// mounted — would otherwise be reported as a missing secret and hide the real fault.
    /// </remarks>
    private static async Task<T?> ReadAsync<T>(
        Func<IHttpRequestBuilder> request, JsonTypeInfo<T> answer, string token, string path,
        CancellationToken cancellationToken)
    {
        try
        {
            return await request().Header(TokenHeader, token)
                .SendAsync(answer, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpBuilderException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            throw new SecretNotFoundException(path, ex);
        }
    }

    /// <summary>Returns a usable token, logging in when none is held or the held one has run out.</summary>
    /// <remarks>
    /// Requests that arrive together on an expired lease must not each start a login: an AppRole with a
    /// limited secret_id_num_uses would be spent by the duplicates and the role would lock out.
    /// </remarks>
    private async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_options.Token))
            return _options.Token;

        if (_lease is { } current && current.Expires > DateTimeOffset.UtcNow)
            return current.Token;

        await _login.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var lease = _lease;

            if (lease is null || lease.Expires <= DateTimeOffset.UtcNow)
                lease = _lease = await LoginAsync(cancellationToken).ConfigureAwait(false);

            return lease.Token;
        }
        finally
        {
            _login.Release();
        }
    }

    /// <summary>Replaces the <paramref name="refused"/> token once per lease, and answers null when a refusal already did.</summary>
    /// <remarks>
    /// A 403 reads the same for a token that died before its lease said and for a policy that lacks the
    /// path. One login tells them apart: a token that is refused again was never the problem, and a login
    /// per refused request or per reload interval would fill Vault's token store and spend a secret_id's
    /// uses on nothing. Requests refused together still share the one login, as they did.
    /// </remarks>
    private async Task<string?> RenewRefusedAsync(string refused, CancellationToken cancellationToken)
    {
        await _login.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var held = _lease;

            if (held is not null && !string.Equals(held.Token, refused, StringComparison.Ordinal))
                return held.Token;

            if (held is { WasBoughtByARefusal: true })
                return null;

            var renewed = await LoginAsync(cancellationToken).ConfigureAwait(false);
            _lease = renewed with { WasBoughtByARefusal = true };

            return renewed.Token;
        }
        finally
        {
            _login.Release();
        }
    }

    private async Task<Lease> LoginAsync(CancellationToken cancellationToken)
    {
        var credentials = new Dictionary<string, string?>
        {
            ["role_id"] = _options.RoleId,
            ["secret_id"] = _options.SecretId,
        };

        var answer = await Post("v1/auth/approle/login")
            .AsJson(credentials, VaultJson.Default.DictionaryStringString)
            .SendAsync(VaultAnswers.Login, cancellationToken).ConfigureAwait(false);

        var grant = answer?.Auth;
        var token = grant?.ClientToken
            ?? throw new InvalidOperationException("Vault: the AppRole login response carries no client token.");

        return new Lease(token, Expiry(grant.LeaseDuration ?? 0));
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

    /// <summary>A token, the moment it stops being usable and whether a refusal already bought it, kept together so they cannot disagree.</summary>
    private sealed record Lease(string Token, DateTimeOffset Expires, bool WasBoughtByARefusal = false);

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
