# Data Protection Keys

AuthProxy encrypts its authentication cookie, the cookies it uses during sign-in, and every token it issues
(including [client-credentials tokens](authentication.md#back-channel-client-credentials)) with ASP.NET Core
**Data Protection**. The keys that do the encrypting form a **key ring**.

Every AuthProxy instance has to read what any other instance wrote, and every restart has to keep reading what
the previous run wrote. Without a shared, persistent key ring neither holds:

- With more than one replica, a request that lands on a replica other than the one that signed the caller in
  cannot read the session, so callers are signed out at random, in proportion to load.
- After a restart, or on a platform whose disk is not persistent, every session and token is invalidated.

So any deployment with more than one replica, or on a platform without persistent disks, needs a shared key
store. AuthProxy supports three.

| Store | Use it when | Setting |
|-------|-------------|---------|
| `FileSystem` (default) | One instance, or replicas sharing a persistent volume. | `DataProtectionKeysPath` |
| `AzureBlob` | You run on Azure and want no volume to manage. | `DataProtection:AzureBlob` |
| `Redis` | You already run Redis, or run outside Azure. | `DataProtection:Redis` |

Any of them can be combined with [Azure Key Vault key protection](#protecting-the-key-ring-with-azure-key-vault).

---

## File system (default)

This is the behavior of every earlier release and needs no new setting. Point `DataProtectionKeysPath` at a
directory on a persistent volume mounted at the same path for every replica:

```json
{
  "Cratis": {
    "AuthProxy": {
      "DataProtectionKeysPath": "/mnt/dataprotection-keys"
    }
  }
}
```

With no path, the framework's per-machine default is used, which is neither guaranteed to survive a restart
nor shared between replicas. Keys on a file system are stored unencrypted unless the platform encrypts the
volume — add [Key Vault key protection](#protecting-the-key-ring-with-azure-key-vault) if that matters.

---

## Azure Blob Storage

The key ring is stored as one blob. AuthProxy authenticates to it with
[`DefaultAzureCredential`](https://learn.microsoft.com/dotnet/azure/sdk/authentication/credential-chains#defaultazurecredential-overview),
so in Azure there is **no secret to configure**: a managed identity or workload identity is picked up from the
environment.

```json
{
  "Cratis": {
    "AuthProxy": {
      "DataProtection": {
        "Store": "AzureBlob",
        "AzureBlob": {
          "BlobUri": "https://myaccount.blob.core.windows.net/dataprotection/authproxy-keys.xml"
        }
      }
    }
  }
}
```

| Setting | Meaning |
|---------|---------|
| `DataProtection:Store` | Must be `AzureBlob`. |
| `DataProtection:AzureBlob:BlobUri` | The absolute `https` URI of the blob. **Required.** |
| `DataProtection:ManagedIdentityClientId` | The client ID of a user-assigned managed identity. Leave unset for the system-assigned identity. |

What the deployment has to provide:

- The **container must already exist**. The blob is created on first use.
- The identity AuthProxy runs as needs read and write access to the blob — the
  `Storage Blob Data Contributor` role on the container is enough.
- With a **user-assigned** managed identity, set `ManagedIdentityClientId` to its client ID. Without it,
  `DefaultAzureCredential` looks for the system-assigned identity and fails if there is none.
- The address must be `https`; a bearer token is never sent over plain `http`.

As environment variables:

```bash
Cratis__AuthProxy__DataProtection__Store=AzureBlob
Cratis__AuthProxy__DataProtection__AzureBlob__BlobUri=https://myaccount.blob.core.windows.net/dataprotection/authproxy-keys.xml
```

---

## Redis

The key ring is stored under one Redis key.

```json
{
  "Cratis": {
    "AuthProxy": {
      "DataProtection": {
        "Store": "Redis",
        "Redis": {
          "ConnectionString": "my-cache.redis.cache.windows.net:6380,password=...,ssl=true",
          "Key": "Cratis.AuthProxy:DataProtection-Keys"
        }
      }
    }
  }
}
```

| Setting | Meaning |
|---------|---------|
| `DataProtection:Store` | Must be `Redis`. |
| `DataProtection:Redis:ConnectionString` | A [StackExchange.Redis connection string](https://stackexchange.github.io/StackExchange.Redis/Configuration). **Required.** |
| `DataProtection:Redis:Key` | The Redis key holding the key ring. Defaults to `Cratis.AuthProxy:DataProtection-Keys`. Give each deployment sharing one Redis its own value, or they share a key ring. |

The connection string normally carries a password, so supply it from a secret store or an environment
variable (`Cratis__AuthProxy__DataProtection__Redis__ConnectionString`) rather than a file in source control.

What the deployment has to provide:

- **Persistence.** The key ring lives only in Redis. If Redis loses it — a restart without persistence, an
  eviction — AuthProxy creates a new one and every session and token issued under the old keys stops working.
  Use a Redis with persistence enabled and a no-eviction policy for the database holding this key.
- AuthProxy connects with `abortConnect=false` whatever the connection string says, so a Redis that is down
  while AuthProxy starts does not crash it: the connection keeps retrying in the background, the key ring
  fails to load until Redis is reachable, and the [readiness check](management-listener.md) reports the
  replica as not ready until it is. Tune `connectTimeout` and `syncTimeout` in the connection string to decide
  how long a failing call may take.

---

## Protecting the key ring with Azure Key Vault

Setting a Key Vault key encrypts the key ring before it is written to **whichever store you chose**, so
whoever can read the file, blob or Redis key still cannot read the keys.

```json
{
  "Cratis": {
    "AuthProxy": {
      "DataProtection": {
        "KeyVault": {
          "KeyIdentifier": "https://myvault.vault.azure.net/keys/authproxy-dataprotection"
        }
      }
    }
  }
}
```

| Setting | Meaning |
|---------|---------|
| `DataProtection:KeyVault:KeyIdentifier` | The absolute `https` identifier of the key, for example `https://myvault.vault.azure.net/keys/authproxy-dataprotection`. **Required** when the section is present. |

What the deployment has to provide:

- An **RSA** key in the vault. AuthProxy wraps and unwraps the key ring with it (RSA-OAEP).
- The identity AuthProxy runs as needs permission to wrap and unwrap with that key — the `Key Vault Crypto User`
  role, or an access policy granting `wrapKey` and `unwrapKey`. It authenticates the same way as the blob
  store, including `ManagedIdentityClientId`.

> [!IMPORTANT]
> Turning this on, off, or pointing it at a different key does not convert an existing key ring. AuthProxy
> starts a new one, and everyone is signed out. Do it once, when you adopt a shared store, not as routine
> maintenance.

---

## Choosing the store explicitly

`Store` defaults to `FileSystem`, so existing configuration is unaffected. A contradiction is **refused at
startup**, naming the setting, rather than resolved by picking one:

| Configuration | Why it is refused |
|---------------|-------------------|
| `Store` is `AzureBlob` without `AzureBlob:BlobUri`, or `Redis` without `Redis:ConnectionString` | The chosen store has nowhere to write. |
| `DataProtectionKeysPath` set while `Store` is `AzureBlob` or `Redis` | The path would be ignored and the key ring written somewhere else. |
| An `AzureBlob` or `Redis` section present while `Store` names the other store | The section would be ignored. |
| A blob URI or Key Vault identifier that is not an absolute `https` URI | It could never authenticate. |

---

## Multi-replica checklist

1. Pick one store and configure it identically on **every** replica.
2. Give the identity every replica runs as access to that store (and to the vault key, if used).
3. Enable the [management listener](management-listener.md) and use `/health/ready` as the readiness probe.
   It performs a `Protect`/`Unprotect` round-trip through the configured key ring on every call, so a replica
   that cannot load the key ring from the store is kept out of rotation instead of failing sign-ins. Data
   Protection keeps the loaded key ring in memory and re-reads the store periodically, so an outage that
   begins after a replica is running does not sign its callers out; it surfaces when the ring is next
   refreshed or a new key has to be written.
4. Keep the application name `Cratis.AuthProxy`. AuthProxy sets it itself; it is part of what makes replicas
   share keys, and it cannot be changed through configuration.
5. Expect a new key ring, and a sign-out for everyone, when you move from one store to another. Keys are not
   copied between stores.
