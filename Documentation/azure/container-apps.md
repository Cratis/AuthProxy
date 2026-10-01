# AuthProxy on Azure Container Apps

AuthProxy runs on Container Apps as one container app with **external** ingress, in front of backends and
frontends that are container apps with **internal** ingress. Read the [overview](index.md) first: it covers
the Entra registration and the settings both platforms share.

The decision that matters here is how much you trust the other apps in the environment. Internal ingress does
not mean "reachable only by AuthProxy". See [Isolating backends](#isolating-backends).

---

## Create the apps

Use a **user-assigned managed identity** for AuthProxy. Its Key Vault secret reference and its storage and
vault role assignments all have to exist before the app starts, and a system-assigned identity does not exist
until the app has been created.

```bash
az identity create --resource-group $rg --name id-authproxy
identityId=$(az identity show --resource-group $rg --name id-authproxy --query id -o tsv)
identityClientId=$(az identity show --resource-group $rg --name id-authproxy --query clientId -o tsv)
```

Give the identity the `Key Vault Secrets User` role on the client secret, the `Key Vault Crypto User` role on
the Data Protection key, and `Storage Blob Data Contributor` on the blob container. Then create AuthProxy:

```bash
az containerapp create --resource-group $rg --name authproxy --environment $env \
  --image docker.io/cratis/authproxy:<version> \
  --user-assigned $identityId \
  --ingress external --target-port 8080 \
  --min-replicas 2 \
  --secrets "entra-client-secret=keyvaultref:$secretUri,identityref:$identityId" \
  --env-vars \
    Cratis__AuthProxy__Authentication__OidcProviders__0__Name=Microsoft \
    Cratis__AuthProxy__Authentication__OidcProviders__0__Type=Microsoft \
    Cratis__AuthProxy__Authentication__OidcProviders__0__Authority=https://login.microsoftonline.com/$directoryTenantId/v2.0 \
    Cratis__AuthProxy__Authentication__OidcProviders__0__ClientId=$clientId \
    Cratis__AuthProxy__Authentication__OidcProviders__0__ClientSecret=secretref:entra-client-secret \
    Cratis__AuthProxy__Authentication__OidcProviders__0__CanonicalIdentity__ProviderKey=entra-workforce \
    Cratis__AuthProxy__Authentication__OidcProviders__0__CanonicalIdentity__SubjectClaimType=oid \
    Cratis__AuthProxy__Services__portal__Backend__BaseUrl=https://$backendFqdn/ \
    Cratis__AuthProxy__Services__portal__Frontend__BaseUrl=https://$frontendFqdn/ \
    Cratis__AuthProxy__Ingress__Mode=TrustAny \
    Cratis__AuthProxy__Ingress__ForwardLimit=1 \
    Cratis__AuthProxy__DataProtection__Store=AzureBlob \
    Cratis__AuthProxy__DataProtection__AzureBlob__BlobUri=https://$account.blob.core.windows.net/dataprotection/authproxy-keys.xml \
    Cratis__AuthProxy__DataProtection__KeyVault__KeyIdentifier=https://$vault.vault.azure.net/keys/authproxy-dataprotection \
    Cratis__AuthProxy__DataProtection__ManagedIdentityClientId=$identityClientId \
    Cratis__AuthProxy__Management__Port=9110 \
    Cratis__AuthProxy__Management__BindAddress=0.0.0.0
```

- **Target port 8080.** The AuthProxy image listens on 8080. Ingress publishes it on 443 and redirects port 80
  to it.
- **At least two replicas**, and a shared key store, so a restart or scale-out does not sign users out. With
  the shared [Data Protection keys](index.md#data-protection-keys), any replica can read any session. Leave
  [session affinity](https://learn.microsoft.com/azure/container-apps/sticky-sessions) off.
- **The client secret** is a Key Vault reference resolved by the managed identity and passed to the container
  as `secretref:`. It never appears in the app's settings.
- **Leave Authentication off** on the container app, as the overview explains.

### Service addresses

Use the backend's **internal FQDN**, which is `<app>.internal.<environment-id>.<region>.azurecontainerapps.io`:

```bash
backendFqdn=$(az containerapp show --resource-group $rg --name portal-api \
  --query properties.configuration.ingress.fqdn -o tsv)
```

Container Apps also documents `http://<app-name>` for calls inside an environment. With the default ingress
setting (`allowInsecure` is `false`) plain HTTP is redirected to HTTPS, and AuthProxy passes a redirect from a
backend on to the caller rather than following it, so use the `https` FQDN and keep the traffic encrypted.

### Trusted proxies

Container Apps ingress overwrites `X-Forwarded-Proto` and adds the client's address to `X-Forwarded-For`,
and Microsoft's documentation states that only the rightmost address is provided by the platform. AuthProxy
takes only that one with a `ForwardLimit` of `1`, so a value a caller wrote further left in the header is never
read.

The address AuthProxy sees as the peer is the environment's ingress proxy, and the platform publishes no
range for it. The settings above therefore use `Mode=TrustAny`, which is right **only because nothing other
than the platform's ingress can connect to the container's port 8080**: the platform routes every request
between apps through its proxy layer, not directly to a replica. If you also run
something that can open a connection straight to the replica, switch to `Mode=Configured` and name the real
peers with `TrustedProxies` instead. `TrustAny` ignores `TrustedProxies` even when you populate it.
See [Trusted proxies](../configuration/trusted-proxies.md#modes).

### Adding an upstream proxy

Putting Azure Front Door or Application Gateway in front of AuthProxy does not make the Container Apps
origin private. With external ingress, a caller can still bypass that upstream proxy and call the ACA origin
hostname directly. **Keep `ForwardLimit=1` while that origin is publicly reachable in `Mode=TrustAny`.**
If you raise it to `2`, a direct caller can send `X-Forwarded-For: 203.0.113.123`; Container Apps appends the
real caller address, and AuthProxy consumes both entries and records the forged address in sign-in
notifications. Adding upstream ranges to `TrustedProxies` cannot prevent this in `TrustAny` mode.

Before increasing the limit, choose one of these boundaries:

- Restrict access to AuthProxy's origin to the intended upstream proxy, including any routes from other apps
  in the environment. Use a network restriction that prevents bypass; an upstream hostname alone is not an
  access restriction. Then set the limit to the number of verified forwarded hops.
- Use `Mode=Configured` with verified trusted hops in `TrustedProxies`, including the actual Container Apps
  ingress peer and the upstream proxy. Container Apps publishes no ingress peer range, so do not guess one
  or use a catch-all range. If you cannot verify every trusted hop, keep `ForwardLimit=1`.

**Require a direct-origin spoofed-header check before increasing `ForwardLimit`:** from outside the intended
upstream proxy, send `X-Forwarded-For: 203.0.113.123` directly to AuthProxy's ACA origin hostname, not the
Front Door or Application Gateway hostname. With an origin restriction, the platform must refuse that request
before it reaches AuthProxy. With `Configured` mode, complete a test sign-in carrying the spoofed header and
confirm that the sign-in notification records the actual caller address, never `203.0.113.123`. Also confirm
that a normal sign-in through the upstream proxy records the real client address. Test the proposed higher
limit in a non-production deployment with the same boundary before applying it in production; do not increase
it if the check fails or the recorded address cannot be observed.

### Health probes

The management listener is a second port that the platform can probe, so use it:

```yaml
containers:
  - name: authproxy
    image: docker.io/cratis/authproxy:<version>
    probes:
      - type: Liveness
        httpGet:
          path: /health/live
          port: 9110
      - type: Readiness
        httpGet:
          path: /health/ready
          port: 9110
```

Apply it by updating the app with a YAML definition that carries this `probes` list. Readiness runs the Data
Protection round trip, so a replica that cannot load the key ring from storage is kept out of rotation.
Probe port 9110 matches `Management__Port` above.

`Management__BindAddress=0.0.0.0` is needed because the default is loopback, which a probe sent to the
replica from outside the container cannot reach. The management port is not the ingress target port, so
ingress does not publish it. It answers only `/health/live` and `/health/ready`, with a fixed short body. See
[Management listener](../configuration/management-listener.md). If a replica never becomes ready, check this
bind address first.

### Timeouts and streaming

Ingress ends a request that is idle for **four minutes** by default (240 seconds). A Container Apps environment
on the premium ingress can raise that to up to 30 minutes in its ingress settings. AuthProxy's own
`ActivityTimeout` defaults to five minutes, so on a default environment the platform cuts a quiet WebSocket
or Server-Sent Events stream first. Send a heartbeat every 15 to 30 seconds, and raise both limits together if
a stream has to be quiet for longer. See
[Timeouts and streaming](../configuration/services.md#timeouts-and-streaming).

---

## Isolating backends

Create each backend and frontend container app with **internal** ingress:

```bash
az containerapp create --resource-group $rg --name portal-api --environment $env \
  --image <backend-image> --ingress internal --target-port 8080
```

From outside the environment, an internal app's name resolves and the TLS handshake succeeds, but the
environment's proxy answers `404`. That settles the internet, and for a VNet-integrated environment it
settles your own network too: requests from your virtual network count as outside the environment.

**It does not settle the other apps in the environment.** Container Apps documents internal ingress as
reachable from other container apps in the same environment, and an *external* app is also reachable from them.
Any app in the environment can therefore call `https://portal-api.internal...` with a forged
`x-ms-client-principal` header and be believed. Treat the environment as the trust boundary:

1. **Run AuthProxy and the apps it protects in an environment of their own**, in which every app is one you
   would trust with every user's identity. Put anything else, such as other teams' apps, jobs and
   experiments, in a different environment.
2. **Keep the backends out of any environment-level HTTP route configuration.** An app with internal ingress
   can still receive outside traffic when a route configuration names it as a target.
3. **For an environment that only your network should reach**, create it as an internal environment, and
   publish AuthProxy with external ingress, which then listens on the environment's internal load balancer.
   Container Apps documents the two settings together: the environment decides whether there is a public
   endpoint, and the app's ingress decides whether it is published at that boundary.
4. **Do not rely on IP restrictions** on a backend to separate it from apps in the same environment. They
   filter by caller address, and in-environment traffic arrives through the platform's proxy layer.

Container Apps client certificates (`clientCertificateMode`) would tie a backend to AuthProxy by
certificate, but AuthProxy does not present a client certificate to the services it proxies to, so they cannot
be used for this today. Per-request signing of the forwarded identity, which would make environment
membership irrelevant, is tracked in [Cratis/AuthProxy#139](https://github.com/Cratis/AuthProxy/issues/139).

### Prove it

First confirm that your chosen endpoint returns `2xx` for the probe's forged principal from an allowed
location, as the [direct-access test](index.md#test-that-a-backend-cannot-be-reached-directly) explains. Then
run it twice:

- Against that endpoint at `https://portal-api.internal.<environment-id>.<region>.azurecontainerapps.io/`
  from outside the environment, such as your pipeline runner. It must be refused. To accept the platform's
  `404`, configure both that status and a distinctive platform-refusal body marker; an application's own
  `404` must not pass.
- Against the same address from a **container app in the same environment that is not AuthProxy**. It will be
  answered. That is not a bug in your configuration; it is the boundary described above. If that second app
  is not supposed to be able to impersonate users, it belongs in another environment.

Then sign in through AuthProxy and confirm the application works.
