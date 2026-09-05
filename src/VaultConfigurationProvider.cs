using System.Net.Sockets;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Feeds Vault KV v2 secrets into the configuration, with retries, an optional mode and background reload.</summary>
public sealed class VaultConfigurationProvider : ConfigurationProvider, IDisposable
{
    private const int DefaultLoadTimeoutSeconds = 30;
    private const int DefaultReconnectIntervalSeconds = 5;

    private readonly VaultOptions _options;
    private readonly IVaultReader _reader;
    private readonly bool _ownsReader;

    /// <summary>Never disposed: a Dispose racing a load in flight would make its Release throw.</summary>
    /// <remarks>
    /// SemaphoreSlim only needs disposing once AvailableWaitHandle has been touched, and it never is here.
    /// </remarks>
    private readonly SemaphoreSlim _loading = new(1, 1);
    private PeriodicRefresh? _refresh;
    private Dictionary<string, int> _versions = new(StringComparer.Ordinal);
    private bool _loadedOnce;
    private volatile bool _disposed;

    /// <summary>Creates the provider; without an explicit reader the secrets come over HTTP.</summary>
    public VaultConfigurationProvider(VaultOptions options, IVaultReader? reader = null)
    {
        _options = options;
        _ownsReader = reader is null;

        Validate(options, _ownsReader);

        _reader = reader ?? new VaultHttpClient(options);
    }

    /// <summary>Loads every configured secret within the time budget.</summary>
    public override void Load()
    {
        var timeout = TimeSpan.FromSeconds(_options.LoadTimeoutSeconds ?? DefaultLoadTimeoutSeconds);
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            LoadWithRetriesAsync(cts.Token).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (_options.Optional && !IsPermanent(ex))
        {
            Log($"Vault: the source is optional and was skipped. {ex.Message}", ex);
        }
        catch (Exception ex) when (cts.IsCancellationRequested && !IsPermanent(ex))
        {
            throw new TimeoutException(
                $"Vault: could not load the configuration from '{_options.Address}' within {timeout.TotalSeconds:0} seconds. " +
                "Increase Vault:LoadTimeoutSeconds, or set Vault:Optional to start without Vault.", ex);
        }

        StartRefreshing();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        _refresh?.Dispose();

        if (_ownsReader && _reader is IDisposable disposable)
            disposable.Dispose();
    }

    internal async Task ReloadAsync(CancellationToken cancellationToken)
    {
        await _loading.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_loadedOnce && await IsUnchangedAsync(cancellationToken).ConfigureAwait(false))
                return;

            await LoadOnceAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _loading.Release();
        }
    }

    private async Task LoadWithRetriesAsync(CancellationToken cancellationToken)
    {
        var delay = TimeSpan.FromSeconds(_options.ReconnectIntervalSeconds ?? DefaultReconnectIntervalSeconds);
        while (true)
        {
            try
            {
                await LoadGuardedAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested && IsTransient(ex))
            {
                Log($"Vault: {ex.Message} Retry in {delay.TotalSeconds:0} seconds.", ex);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>A failure worth waiting out: the network or the server, never the configuration.</summary>
    /// <remarks>
    /// Listed rather than excluded, so a failure nobody anticipated fails with its own message instead of
    /// spending the whole load budget and then reporting a Vault timeout that never happened.
    /// HttpBuilderException derives from HttpRequestException, which covers every refused status.
    /// TaskCanceledException here is one request timing out on its own — the budget running out is told
    /// apart by the caller's token, not by the exception.
    /// </remarks>
    private static bool IsTransient(Exception exception) =>
        exception is HttpRequestException or IOException or SocketException or TimeoutException
            or TaskCanceledException;

    /// <summary>A failure Optional must not hide: the configuration is wrong, not the server away.</summary>
    /// <remarks>
    /// Deliberately the opposite shape to <see cref="IsTransient"/>. Retrying asks "could waiting help",
    /// which only a listed few can answer yes to; Optional asks "is this my mistake", and everything that
    /// is not has to let the application start.
    /// </remarks>
    private static bool IsPermanent(Exception exception) =>
        exception is SecretNotFoundException or InvalidOperationException;

    /// <summary>Loads under the gate that keeps the startup load and a background refresh from overlapping.</summary>
    private async Task LoadGuardedAsync(CancellationToken cancellationToken)
    {
        await _loading.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await LoadOnceAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _loading.Release();
        }
    }

    private async Task LoadOnceAsync(CancellationToken cancellationToken)
    {
        if (_options.Secrets is not { Length: > 0 } secrets)
        {
            Log("Vault: no secrets are configured, nothing to load.", null);
            return;
        }

        var data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var versions = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var secret in secrets)
        {
            var payload = await _reader.ReadSecretAsync(secret, cancellationToken).ConfigureAwait(false);

            if (payload.Version is { } version)
                versions[Identify(secret)] = version;

            foreach (var (key, value) in SecretKeys.Of(secret, payload.Data, _options.ExpandJsonValues))
                data[key] = value;
        }

        var changed = !SameData(Data, data);
        Data = data;
        _versions = versions;
        _loadedOnce = true;

        if (changed)
            OnReload();

        Log("Vault: the configuration has been loaded successfully.", null);
    }

    /// <summary>Starts the background refresh once the first load has settled.</summary>
    /// <remarks>
    /// Not in the constructor: when the load throws, ConfigurationRoot never finishes building and nothing
    /// is left holding the provider to dispose it, so a loop started earlier would poll Vault for the life
    /// of a process that has already failed to start.
    /// </remarks>
    private void StartRefreshing()
    {
        if (_disposed || _refresh is not null || _options.ReloadCheckIntervalSeconds is not { } seconds)
            return;

        _refresh = new PeriodicRefresh(TimeSpan.FromSeconds(seconds), RefreshOnceAsync);
        _refresh.Start();
    }

    private async Task RefreshOnceAsync(CancellationToken stopping)
    {
        var timeout = TimeSpan.FromSeconds(_options.LoadTimeoutSeconds ?? DefaultLoadTimeoutSeconds);
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        attempt.CancelAfter(timeout);

        try
        {
            await ReloadAsync(attempt.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            if (stopping.IsCancellationRequested)
                return;

            Log($"Vault: the reload failed, the previous values stay in place. {ex.Message}", ex);
        }
    }

    private async Task<bool> IsUnchangedAsync(CancellationToken cancellationToken)
    {
        if (_options.Secrets is not { Length: > 0 } secrets)
            return true;

        foreach (var secret in secrets)
        {
            if (secret.Version is not null)
                continue;

            var current = await ProbeVersionAsync(secret, cancellationToken).ConfigureAwait(false);
            if (current is not { } version || !_versions.TryGetValue(Identify(secret), out var known) || known != version)
                return false;
        }

        return true;
    }

    /// <summary>Reads the current version, answering null when the probe is refused or fails.</summary>
    /// <remarks>
    /// The probe reads metadata, a capability a policy granting only data does not carry. A refused probe
    /// has to fall back to the full read: aborting the cycle instead would freeze the values for good and
    /// say so only once per interval.
    /// </remarks>
    private async Task<int?> ProbeVersionAsync(VaultSecret secret, CancellationToken cancellationToken)
    {
        try
        {
            return await _reader.ReadSecretVersionAsync(secret, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"Vault: could not read the version of '{secret.Path}', re-reading it in full. {ex.Message}", ex);
            return null;
        }
    }

    /// <summary>Names a secret by what it points at, so a reordered Secrets array keeps its known versions.</summary>
    /// <remarks>
    /// Resolves the mount the way the reader does. An empty MountPath means "take the shared one" there,
    /// and a name that disagreed would file the version under a secret the request never asks for.
    /// </remarks>
    private string Identify(VaultSecret secret) =>
        $"{(string.IsNullOrEmpty(secret.MountPath) ? _options.MountPath : secret.MountPath)}/{secret.Path}";

    /// <summary>Rejects a configuration the provider cannot act on, naming the setting that is wrong.</summary>
    /// <remarks>
    /// Transport settings are checked only when the provider builds its own reader: an injected one
    /// carries its own connection, and an address it never uses must not fail the host.
    /// </remarks>
    private static void Validate(VaultOptions options, bool ownsReader)
    {
        foreach (var secret in options.Secrets ?? [])
        {
            if (string.IsNullOrWhiteSpace(secret.Path))
                throw new InvalidOperationException(
                    $"Vault: a secret in '{nameof(VaultOptions.Secrets)}' has no '{nameof(VaultSecret.Path)}'.");

            if (string.IsNullOrWhiteSpace(secret.MountPath) && string.IsNullOrWhiteSpace(options.MountPath))
                throw new InvalidOperationException(
                    $"Vault: the secret '{secret.Path}' has no mount path. " +
                    $"Set 'Vault:{nameof(VaultOptions.MountPath)}' or the secret's '{nameof(VaultSecret.MountPath)}'.");
        }

        ValidateSeconds(options.LoadTimeoutSeconds, nameof(VaultOptions.LoadTimeoutSeconds));
        ValidateSeconds(options.ReloadCheckIntervalSeconds, nameof(VaultOptions.ReloadCheckIntervalSeconds));
        ValidateSeconds(options.ReconnectIntervalSeconds, nameof(VaultOptions.ReconnectIntervalSeconds));
        ValidateSeconds(options.ConnectionLifetimeSeconds, nameof(VaultOptions.ConnectionLifetimeSeconds));

        if (!ownsReader)
            return;

        if (string.IsNullOrWhiteSpace(options.Address))
            throw new InvalidOperationException($"Vault: '{nameof(VaultOptions.Address)}' is not configured.");

        if (!Uri.TryCreate(options.Address, UriKind.Absolute, out var address) ||
            (address.Scheme != Uri.UriSchemeHttp && address.Scheme != Uri.UriSchemeHttps))
            throw new InvalidOperationException(
                $"Vault: '{nameof(VaultOptions.Address)}' must be an absolute http or https URI, " +
                $"not '{options.Address}'.");

        if (string.IsNullOrEmpty(options.Token) &&
            (string.IsNullOrEmpty(options.RoleId) || string.IsNullOrEmpty(options.SecretId)))
            throw new InvalidOperationException(
                $"Vault: set '{nameof(VaultOptions.Token)}', or both '{nameof(VaultOptions.RoleId)}' and " +
                $"'{nameof(VaultOptions.SecretId)}' for an AppRole login.");
    }

    private static void ValidateSeconds(int? seconds, string name)
    {
        if (seconds is < 1)
            throw new InvalidOperationException($"Vault: '{name}' must be at least one second, not {seconds}.");
    }

    private static bool SameData(IDictionary<string, string?> left, IDictionary<string, string?> right)
    {
        if (left.Count != right.Count)
            return false;

        foreach (var (key, value) in left)
        {
            if (!right.TryGetValue(key, out var other) || !string.Equals(value, other, StringComparison.Ordinal))
                return false;
        }

        return true;
    }

    private void Log(string message, Exception? exception)
    {
        if (_options.Logger is { } logger)
        {
            logger(message, exception);
            return;
        }

        if (exception is not null)
            Console.Error.WriteLine(message);
    }
}
