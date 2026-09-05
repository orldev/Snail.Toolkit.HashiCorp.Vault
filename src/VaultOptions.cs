namespace Snail.Toolkit.HashiCorp.Vault;

/// <summary>Connection, authentication and behavior settings of the Vault configuration source.</summary>
public sealed class VaultOptions
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

    /// <summary>Keeps values already provided by other configuration sources; on by default.</summary>
    /// <remarks>
    /// Registers the Vault source ahead of every other one, so the precedence is the one
    /// <c>IConfiguration</c> already has rather than a second rule layered on top of it. Only
    /// <c>AddVault</c> places the source, so a source added by hand does not see this.
    /// </remarks>
    public bool KeepExistingValues { get; set; } = true;

    /// <summary>Turns a secret value carrying a JSON document into sections rather than one opaque string; on by default.</summary>
    /// <remarks>
    /// Only a whole value is unwrapped, never a member inside an already structured one, because a KV v2
    /// secret is a flat map and only its values can be documents. Turn it off when a secret legitimately
    /// holds text that happens to parse as JSON and has to reach the application unchanged.
    /// </remarks>
    public bool ExpandJsonValues { get; set; } = true;

    /// <summary>Lets the application start when Vault is unreachable; with reload enabled the secrets arrive once it recovers.</summary>
    /// <remarks>
    /// Covers an unreachable Vault, not a wrong configuration: a secret the server answers for but does
    /// not have still fails the start, because a mistyped path would otherwise look like a healthy one.
    /// </remarks>
    public bool Optional { get; set; }

    /// <summary>Total time budget for one load in seconds, retries included; 30 by default.</summary>
    public int? LoadTimeoutSeconds { get; set; }

    /// <summary>Background re-check interval in seconds; reload is off when not set.</summary>
    public int? ReloadCheckIntervalSeconds { get; set; }

    /// <summary>Delay between retries within one load, in seconds; 5 by default.</summary>
    public int? ReconnectIntervalSeconds { get; set; }

    /// <summary>How long a pooled connection is kept before it is re-established, in seconds; 120 by default.</summary>
    /// <remarks>
    /// A connection held for the life of the process keeps talking to the address it first resolved, so a
    /// Vault endpoint that moves — a load balancer, a service, a failover — is never noticed.
    /// </remarks>
    public int ConnectionLifetimeSeconds { get; set; } = 120;

    /// <summary>Adjusts the transport the client builds: a private certificate authority, a client certificate, a proxy.</summary>
    /// <remarks>
    /// Not bindable from configuration, because certificates and proxies are objects rather than settings.
    /// Ignored when the caller supplies its own <see cref="HttpClient"/>.
    /// </remarks>
    public Action<SocketsHttpHandler>? ConfigureTransport { get; set; }

    /// <summary>Diagnostics sink for a provider that runs before logging exists.</summary>
    /// <remarks>
    /// Without one only failures are written, and to standard error: a reload that keeps failing has to
    /// stay visible, while a successful one is output on the host's stdout that nobody asked for.
    /// </remarks>
    public Action<string, Exception?>? Logger { get; set; }

    /// <summary>Secrets to read.</summary>
    public VaultSecret[]? Secrets { get; set; }
}
