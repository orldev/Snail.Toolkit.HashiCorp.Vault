## HashiCorp Vault

HashiCorp Vault KV v2 secrets as a .NET `IConfiguration` source: AppRole or token authentication, per-secret configuration sections, background reload. Talks to the Vault HTTP API directly — no VaultSharp dependency.

#### Connecting the configuration

```c#
builder.Configuration.AddVault();
```

`WebApplicationBuilder` and `Host.CreateApplicationBuilder` already provide appsettings and environment variables, so the `Vault` section is ready to be read. For a bare `ConfigurationBuilder` there is `AddVaultWithAppSettings()`, which adds all three, or explicit options:

```c#
builder.Configuration.AddVault(options =>
{
    options.Address = "http://127.0.0.1:8200";
    options.Token = "root";
    options.MountPath = "secret";
    options.Secrets = [new VaultSecret(path: "mongodb")];
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
    "KeepExistingValues" : true,       // - optional
    "Optional" : false,                // - optional: start even when Vault is down
    "LoadTimeoutSeconds" : 30,         // - optional
    "ReconnectIntervalSeconds" : 5,    // - optional
    "ReloadCheckIntervalSeconds" : 60, // - optional: enables background reload
    "Secrets" : [
      {
        "Path" : "project/mongodb",
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

A secret at path `project/mongodb` with keys `Connection` and `Database` becomes `Mongodb:Connection` and `Mongodb:Database` (or `project/mongodb:*` without a prefix). A value that itself carries JSON is unwrapped into nested sections, arrays included, so a whole `Serilog` block can live in one Vault key.

#### Behavior

- The initial load retries inside the `LoadTimeoutSeconds` budget and then fails with a clear `TimeoutException`; `Optional: true` starts the application anyway.
- With `ReloadCheckIntervalSeconds` set, the provider probes secret versions in the background, re-reads on change and raises the configuration reload token — `IOptionsMonitor<T>` sees rotations. An optional source that started without Vault picks the secrets up the same way.
- An expired AppRole token is renewed and the request repeated automatically.
- A missing secret raises `SecretNotFoundException` right away — no pointless retries.
- `Logger` on the options receives progress and failures; console output by default.

## License

Snail.Toolkit.HashiCorp.Vault is a free and open source project, released under the permissible [MIT license](LICENSE).