## HashiCorp Vault

HashiCorp Vault KV v2 secrets as a .NET `IConfiguration` source: AppRole or token authentication, per-secret configuration sections, background reload. Talks to the Vault HTTP API directly — no VaultSharp dependency.

#### Connecting the configuration

```c#
builder.Configuration.AddVault();
```

`WebApplicationBuilder` and `Host.CreateApplicationBuilder` already provide appsettings and environment variables, so the `Vault` section is ready to be read. A bare `ConfigurationBuilder` has to supply them itself, with the `Microsoft.Extensions.Configuration.Json` and `.EnvironmentVariables` packages it needs for its own code:

```c#
var configuration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .AddVault()
    .Build();
```

Or pass the options explicitly, with no `Vault` section at all:

```c#
builder.Configuration.AddVault(options =>
{
    options.Address = "http://127.0.0.1:8200";
    options.Token = "root";
    options.MountPath = "secret";
    options.Secrets = [new VaultSecret(Path: "Mongodb")];
});
```

#### Sample configuration appsettings.json

```json lines
{
  "Vault": {
    "Address" : "http://127.0.0.1:8200",
    "RoleId" : "projects-id-role",
    "SecretId" : "projects-id-secret",
    "MountPath" : "secret",
    "Token" : null,                    // - dev only: skips AppRole login
    "KeepExistingValues" : true,       // - optional: everything else overrides Vault
    "Optional" : false,                // - optional: start even when Vault is down
    "LoadTimeoutSeconds" : 30,         // - optional
    "ReconnectIntervalSeconds" : 5,    // - optional
    "ReloadCheckIntervalSeconds" : 60, // - optional: enables background reload
    "ConnectionLifetimeSeconds" : 120, // - optional: how often a pooled connection is re-established
    "ExpandJsonValues" : true,         // - optional: unwrap a value that carries a JSON document
    "Secrets" : [
      {
        "Path" : "project/Mongodb",
        "ConfigurationPrefix" : "Mongodb", // - optional: target section, "" for the root
        "MountPath" : "secret",          // - optional
        "Version" : 1,                   // - optional
        "Keys" : ["Connection", "Database"] // - optional
      }
    ]
  }
}
```

#### How the secrets land

A secret at path `project/Mongodb` with keys `Connection` and `Database` becomes `Mongodb:Connection` and `Mongodb:Database` (or `project/Mongodb:*` without a prefix).

A value that itself carries JSON is unwrapped into nested sections, arrays included, so a whole `Serilog` block can live in one Vault key. Only a whole value is unwrapped, never a member inside an already structured one. Set `ExpandJsonValues: false` when a secret legitimately holds text that happens to parse as JSON and has to reach the application unchanged.

#### Behavior

- The initial load retries inside the `LoadTimeoutSeconds` budget and then fails with a clear `TimeoutException`; `Optional: true` starts the application anyway.
- `KeepExistingValues: true` registers the Vault source ahead of every other one, so appsettings, environment variables and the command line override it. Set it to `false` and Vault is registered last and wins. The precedence is the one `IConfiguration` already has — only `AddVault` places the source, so a source added by hand ignores the setting.
- `Optional` covers an unreachable Vault, not a wrong configuration. A missing address, missing credentials or an interval below a second fail the start whatever it is set to, and so does a secret the server answers for but does not have.
- With `ReloadCheckIntervalSeconds` set, the provider probes secret versions in the background, re-reads on change and raises the configuration reload token — `IOptionsMonitor<T>` sees rotations. An optional source that started without Vault picks the secrets up the same way.
- The AppRole token is replaced before its lease runs out, so an expiry does not cost a failed request; a token refused anyway is renewed once and the request repeated, however many requests were refused together.
- A missing secret raises `SecretNotFoundException` right away — no pointless retries — and carries the path it was asked for together with the refusal that produced it.
- The version probe reads metadata. Where the policy does not allow that, the probe is skipped and the secret is re-read in full rather than left frozen.
- Connections are re-established every `ConnectionLifetimeSeconds`, so a Vault endpoint that moves behind a load balancer is noticed. `ConfigureTransport` on the options reaches the handler for a private certificate authority, a client certificate or a proxy.
- `Logger` on the options receives progress and failures. Without one, only failures are written, and to standard error.

## License

Snail.Toolkit.HashiCorp.Vault is a free and open source project, released under the permissible [MIT license](LICENSE).