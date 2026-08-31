using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Snail.Toolkit.HashiCorp.Vault.Http;

namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Feeds Vault KV v2 secrets into the configuration, with retries, an optional mode and background reload.</summary>
public class VaultConfigurationProvider : ConfigurationProvider, IDisposable
{
    private const int DefaultLoadTimeoutSeconds = 30;
    private const int DefaultReconnectIntervalSeconds = 5;

    private readonly VaultOptions _options;
    private readonly IConfigurationRoot _configurationRoot;
    private readonly IVaultReader _reader;
    private readonly bool _ownsReader;
    private readonly ReloadTimer? _timer;
    private readonly IDisposable? _reloadSubscription;
    private Dictionary<int, int> _versions = new();
    private bool _loadedOnce;

    /// <summary>Creates the provider; without an explicit reader the secrets come over HTTP.</summary>
    public VaultConfigurationProvider(VaultOptions options, IConfigurationRoot configurationRoot,
        IVaultReader? reader = null)
    {
        _options = options;
        _configurationRoot = configurationRoot;
        _ownsReader = reader is null;
        _reader = reader ?? new VaultHttpClient(options);

        if (_options.ReloadCheckIntervalSeconds is { } seconds)
        {
            _timer = new ReloadTimer(TimeSpan.FromSeconds(seconds));
            _reloadSubscription = ChangeToken.OnChange(_timer.Watch, ReloadCheck);
        }
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
        catch (Exception ex) when (_options.Optional)
        {
            Log($"Vault: the source is optional and was skipped. {ex.Message}", ex);
        }
        catch (OperationCanceledException ex)
        {
            throw new TimeoutException(
                $"Vault: could not load the configuration from '{_options.Address}' within {timeout.TotalSeconds:0} seconds. " +
                "Increase Vault:LoadTimeoutSeconds, or set Vault:Optional to start without Vault.", ex);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _reloadSubscription?.Dispose();
        _timer?.Dispose();

        if (_ownsReader && _reader is IDisposable disposable)
            disposable.Dispose();
    }

    internal async Task ReloadAsync(CancellationToken cancellationToken)
    {
        if (_loadedOnce && await IsUnchangedAsync(cancellationToken).ConfigureAwait(false))
            return;

        await LoadOnceAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task LoadWithRetriesAsync(CancellationToken cancellationToken)
    {
        var delay = TimeSpan.FromSeconds(_options.ReconnectIntervalSeconds ?? DefaultReconnectIntervalSeconds);
        while (true)
        {
            try
            {
                await LoadOnceAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not SecretNotFoundException)
            {
                Log($"Vault: {ex.Message} Retry in {delay.TotalSeconds:0} seconds.", ex);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
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
        var versions = new Dictionary<int, int>();

        for (var i = 0; i < secrets.Length; i++)
        {
            var payload = await _reader.ReadSecretAsync(secrets[i], cancellationToken).ConfigureAwait(false);
            versions[i] = payload.Version;
            MapSecret(secrets[i], payload.Data, data);
        }

        var changed = _loadedOnce && !SameData(Data, data);
        Data = data;
        _versions = versions;
        _loadedOnce = true;

        if (changed)
            OnReload();

        Log("Vault: the configuration has been loaded successfully.", null);
    }

    private void ReloadCheck()
    {
        var timeout = TimeSpan.FromSeconds(_options.LoadTimeoutSeconds ?? DefaultLoadTimeoutSeconds);
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            ReloadAsync(cts.Token).ConfigureAwait(false).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Log($"Vault: the reload failed, the previous values stay in place. {ex.Message}", ex);
        }
    }

    private async Task<bool> IsUnchangedAsync(CancellationToken cancellationToken)
    {
        if (_options.Secrets is not { Length: > 0 } secrets)
            return true;

        for (var i = 0; i < secrets.Length; i++)
        {
            if (secrets[i].Version is not null)
                continue;

            var current = await _reader.ReadSecretVersionAsync(secrets[i], cancellationToken).ConfigureAwait(false);
            if (!_versions.TryGetValue(i, out var known) || known != current)
                return false;
        }

        return true;
    }

    private void MapSecret(VaultSecret secret, JsonObject payload, Dictionary<string, string?> data)
    {
        var prefix = secret.ConfigurationPrefix ?? secret.Path ?? string.Empty;

        foreach (var (key, node) in payload)
        {
            if (string.IsNullOrEmpty(key))
                continue;

            if (secret.Keys is { Length: > 0 } && !secret.Keys.Contains(key, StringComparer.OrdinalIgnoreCase))
                continue;

            foreach (var (path, value) in JsonFlattener.Flatten(JsonFlattener.Combine(prefix, key), JsonFlattener.Expand(node)))
            {
                if (_options.KeepExistingValues && _configurationRoot[path] is not null)
                    continue;

                data[path] = value;
            }
        }
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
            logger(message, exception);
        else
            Console.WriteLine(message);
    }
}
