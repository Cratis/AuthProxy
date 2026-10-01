# AuthProxy on Azure App Service

AuthProxy runs on App Service as a Linux custom container, with your backends and frontends as separate App
Service apps (or any other private workload) that only AuthProxy can reach. Read the
[overview](index.md) first: it covers the Entra registration and the settings both platforms share.

---

## Create the AuthProxy app

Create a Linux App Service plan (Basic or higher; a private endpoint, used below, needs one) and a web app
that runs the `cratis/authproxy` image from Docker Hub. Pin a version tag rather than `latest`.

```bash
az appservice plan create --resource-group $rg --name $plan --is-linux --sku P1V3

az webapp create --resource-group $rg --plan $plan --name $authproxy \
  --deployment-container-image-name docker.io/cratis/authproxy:<version>

az webapp identity assign --resource-group $rg --name $authproxy
az webapp update --resource-group $rg --name $authproxy --https-only true
az webapp config set --resource-group $rg --name $authproxy --web-sockets-enabled true --always-on true
```

- **`WEBSITES_PORT=8080`.** App Service assumes a container listens on port 80. The AuthProxy image listens on
  8080, so tell the platform.
- **HTTPS only**, so plain-HTTP requests are redirected before they reach AuthProxy.
- **Web sockets on**, if any service behind AuthProxy uses WebSockets.
- **Always On**, so the app is not unloaded after 20 minutes without traffic. The platform's keep-alive request
  to `/` is answered `401` by AuthProxy, which does it no harm.
- **Managed identity**, for the storage account and Key Vault key used for
  [Data Protection keys](index.md#data-protection-keys).
- **Leave Authentication off**, as the overview explains.

### App settings

Everything below is an app setting, which App Service passes to the container as an environment variable.
`__` in a name is the configuration separator. Keep the client secret out of plain settings by
referencing a Key Vault secret, which the app's managed identity must be allowed to read:

```bash
az webapp config appsettings set --resource-group $rg --name $authproxy --settings \
  WEBSITES_PORT=8080 \
  Cratis__AuthProxy__Authentication__OidcProviders__0__Name=Microsoft \
  Cratis__AuthProxy__Authentication__OidcProviders__0__Type=Microsoft \
  Cratis__AuthProxy__Authentication__OidcProviders__0__Authority=https://login.microsoftonline.com/$directoryTenantId/v2.0 \
  Cratis__AuthProxy__Authentication__OidcProviders__0__ClientId=$clientId \
  "Cratis__AuthProxy__Authentication__OidcProviders__0__ClientSecret=@Microsoft.KeyVault(SecretUri=$secretUri)" \
  Cratis__AuthProxy__Authentication__OidcProviders__0__CanonicalIdentity__ProviderKey=entra-workforce \
  Cratis__AuthProxy__Authentication__OidcProviders__0__CanonicalIdentity__SubjectClaimType=oid \
  Cratis__AuthProxy__Services__portal__Backend__BaseUrl=https://$backend.azurewebsites.net/ \
  Cratis__AuthProxy__Services__portal__Frontend__BaseUrl=https://$frontend.azurewebsites.net/ \
  Cratis__AuthProxy__Services__portal__AnonymousPaths__0=/api/health \
  Cratis__AuthProxy__Ingress__Mode=Configured \
  Cratis__AuthProxy__Ingress__TrustedProxies__0=10.0.0.0/8 \
  Cratis__AuthProxy__Ingress__TrustedProxies__1=172.16.0.0/12 \
  Cratis__AuthProxy__Ingress__TrustedProxies__2=192.168.0.0/16 \
  Cratis__AuthProxy__Ingress__ForwardLimit=1 \
  Cratis__AuthProxy__DataProtection__Store=AzureBlob \
  Cratis__AuthProxy__DataProtection__AzureBlob__BlobUri=https://$account.blob.core.windows.net/dataprotection/authproxy-keys.xml \
  Cratis__AuthProxy__DataProtection__KeyVault__KeyIdentifier=https://$vault.vault.azure.net/keys/authproxy-dataprotection
```

Add the `Authorization` settings from the overview if you require an app role. The trusted-proxy and
`AnonymousPaths` settings are explained next.

### Trusted proxies

App Service terminates TLS at its front ends and reaches your container from a private address. Microsoft's
own ASP.NET Core guidance for App Service trusts the three private ranges, `10.0.0.0/8`, `172.16.0.0/12` and
`192.168.0.0/16`, because the platform does not publish anything narrower. The settings above do the same,
with a `ForwardLimit` of `1` for the App Service front end alone.

Two consequences:

- In multitenant App Service, only the platform front ends connect to the container. The private ranges
  also include your own virtual network, so do not assume that boundary in an App Service Environment or
  when AuthProxy has a private endpoint: a peer that can reach the worker directly may supply trusted
  forwarded headers. Restrict access to the **AuthProxy app**, not just its backends. Use access restrictions
  for its public ingress; private-endpoint traffic bypasses those rules and needs network controls such as
  a subnet network security group with private-endpoint network policies enabled.
- Put Azure Front Door or Application Gateway in front of the app and you have a second hop. Raise
  `ForwardLimit` to `2` and add that service's own address ranges to `TrustedProxies`, because every hop
  that is consumed has to be trusted. For Front Door, also allow only your instance to reach AuthProxy, with an
  access restriction on the `AzureFrontDoor.Backend` service tag and your `X-Azure-FDID` header value;
  otherwise anyone can bypass it and talk to the app's public name.

After the first sign-in, check what AuthProxy recorded. The `ipAddress` your
[sign-in notification](../configuration/sign-in.md) receives should be the user's, not an address inside
Azure. [Trusted proxies](../configuration/trusted-proxies.md#checking-your-work) shows how to read it.

### Health check

App Service's health check requests a path on the site and takes an instance out of rotation when it does not
answer `200` to `299`. It does not follow redirects, and a site with its own authentication must let the
path through anonymously. AuthProxy's own endpoints are no use to it: `/` answers `401`, and the
[management listener](../configuration/management-listener.md) is on a second port, while App Service
sends traffic to the one port named by `WEBSITES_PORT`.

Point the check at a health endpoint of your **backend**, made reachable without a session by declaring it
anonymous. That is the `AnonymousPaths__0=/api/health` setting above; a path under `/api` goes to the
service's backend. It tests AuthProxy and the backend end to end, so an unhealthy backend takes the instance
out of rotation. Declare the narrowest path and make sure it returns nothing sensitive; in a deployment with several services,
a declared prefix is [claimed for the whole proxy](../configuration/services.md#what-it-does-and-does-not-change). Enable **Health
check** under **Monitoring** on the AuthProxy app, give it that path, and run at least two instances, because
App Service does not take its only instance out of rotation.

### Timeouts and streaming

AuthProxy cancels a request that is idle for five minutes by default (`Cratis__AuthProxy__ActivityTimeout`).
App Service's front end also applies an idle limit of its own to a connection; look up its current value in
the App Service documentation, because AuthProxy cannot raise it. Whichever limit is shorter ends a quiet
WebSocket or Server-Sent Events stream, so send a heartbeat every 15 to 30 seconds and treat a dropped
stream as normal on the client. See
[Timeouts and streaming](../configuration/services.md#timeouts-and-streaming).

---

## Isolating backends

Each backend and frontend is its own App Service app, and **each one must refuse everything except
AuthProxy.** There are two ways; pick one per app. The first is the stronger.

**Prerequisite for both alternatives:** put AuthProxy on a **virtual network integration subnet** before
configuring any backend. This is outbound-only; it does not make AuthProxy private.

```bash
az webapp vnet-integration add --resource-group $rg --name $authproxy \
  --vnet $vnet --subnet integration-subnet
```

The subnet must be delegated to `Microsoft.Web/serverFarms` (the command applies the delegation if it is
missing) and cannot be the subnet that holds a private endpoint.

### Private endpoint (recommended)

The backend gets a private IP in your virtual network and no public address. AuthProxy reaches it over its
own virtual network integration.

1. Create a **private endpoint** for each backend in a separate subnet, and a private DNS zone
   `privatelink.azurewebsites.net` linked to the virtual network, so that
   `$backend.azurewebsites.net` resolves to the private address from inside the network:

   ```bash
   az network private-dns zone create --resource-group $rg --name privatelink.azurewebsites.net
   az network private-dns link vnet create --resource-group $rg --zone-name privatelink.azurewebsites.net \
     --name authproxy-link --virtual-network $vnet --registration-enabled false

   az network private-endpoint create --resource-group $rg --name $backend-pe \
     --vnet-name $vnet --subnet private-endpoint-subnet \
     --private-connection-resource-id $(az webapp show --resource-group $rg --name $backend --query id -o tsv) \
     --group-id sites --connection-name $backend-pe-connection

   az network private-endpoint dns-zone-group create --resource-group $rg \
     --endpoint-name $backend-pe --name default \
     --private-dns-zone privatelink.azurewebsites.net --zone-name privatelink.azurewebsites.net
   ```
2. **Disable public network access** on the backend. This is the step that makes it isolated; without it the
   backend keeps answering on its public name as well.

   ```bash
   az resource update --resource-group $rg --name $backend --resource-type Microsoft.Web/sites \
     --set properties.publicNetworkAccess=Disabled
   ```

   On Linux, changing this property restarts the app.

AuthProxy's `BaseUrl` stays `https://$backend.azurewebsites.net/`: the name must match the app's own, and
inside the virtual network it now resolves to the private endpoint.

Remember what a private endpoint does not do: **access restriction rules are not evaluated for traffic
through it.** Anything that can route to the endpoint's address, including other workloads in the network
and peered networks, reaches the backend. Either keep the network to workloads you trust as much as
AuthProxy, or restrict who may connect to the endpoint with a network security group on its subnet (private
endpoint network policies must be enabled on the subnet for the group to apply). Then run the second
[isolation test](index.md#test-that-a-backend-cannot-be-reached-directly) from another workload in the network
to see which of those you actually have.

### Access restrictions with a service endpoint

If a private endpoint is not an option, keep the public name but allow only AuthProxy's integration subnet.

```bash
# Service endpoints for Microsoft.Web must be enabled on the integration subnet.
az network vnet subnet update --resource-group $rg --vnet-name $vnet --name integration-subnet \
  --service-endpoints Microsoft.Web

az webapp config access-restriction add --resource-group $rg --name $backend \
  --rule-name allow-authproxy --action Allow --priority 100 \
  --vnet-name $vnet --subnet integration-subnet

az webapp config access-restriction add --resource-group $rg --name $backend \
  --rule-name allow-authproxy --action Allow --priority 100 \
  --vnet-name $vnet --subnet integration-subnet --scm-site true
```

Adding any rule makes the end of the list an implicit **deny all**, so nothing else is needed. Do the same
for the advanced tools (`scm`) site as shown, because it has its own rule list. Use the subnet rule rather
than an IP address: in the multitenant App Service an IP rule cannot name a virtual network range, and
AuthProxy's public outbound addresses are shared with other apps on the same workers. Any app integrated with
that subnet is allowed through, so keep untrusted apps off it.

### Prove it

First confirm that your chosen endpoint returns `2xx` for the probe's forged principal from an allowed
location, as the [direct-access test](index.md#test-that-a-backend-cannot-be-reached-directly) explains. Then
run it against that endpoint at `https://$backend.azurewebsites.net/` from a machine outside the network:
it must be refused. Identify any expected platform HTTP refusal with both its status and distinctive body
marker; an application `403` or `404` is not a pass. Run it again from a virtual machine or app in the virtual
network that is not AuthProxy. With access restrictions it is refused. With a private endpoint it is refused
only if you restricted the endpoint as described above; otherwise it is answered, and so would be an
attacker's request from that network. Then sign in through
AuthProxy and confirm the application works.
