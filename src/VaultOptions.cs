namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Connection, authentication and behavior settings of the Vault configuration source.</summary>
public class VaultOptions
{
    /// <summary>Vault server URI with port.</summary>
    public string? Address { get; set; }

    /// <summary>Pre-issued token that skips AppRole login — for development against a Vault dev server.</summary>
    public string? Token { get; set; }

    /// <summary>AppRole role identifier.</summary>
    public string? RoleId { get; set; }

    /// <summary>AppRole secret identifier.</summary>
    public string? SecretId { get; set; }

    /// <summary>Mount point of the key-value backend.</summary>
    public string? MountPath { get; set; }

    /// <summary>Keeps values already provided by earlier configuration sources; on by default.</summary>
    public bool KeepExistingValues { get; set; } = true;

    /// <summary>Lets the application start when Vault is unreachable; with reload enabled the secrets arrive once it recovers.</summary>
    public bool Optional { get; set; }

    /// <summary>Total time budget for one load in seconds, retries included; 30 by default.</summary>
    public int? LoadTimeoutSeconds { get; set; }

    /// <summary>Background re-check interval in seconds; reload is off when not set.</summary>
    public int? ReloadCheckIntervalSeconds { get; set; }

    /// <summary>Delay between retries within one load, in seconds; 5 by default.</summary>
    public int? ReconnectIntervalSeconds { get; set; }

    /// <summary>Diagnostics sink for a provider that runs before logging exists; console output by default.</summary>
    public Action<string, Exception?>? Logger { get; set; }

    /// <summary>Secrets to read.</summary>
    public VaultSecret[]? Secrets { get; set; }
}
