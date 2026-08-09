# Custom Error Pages

AuthProxy serves user-friendly HTML pages for error conditions instead of bare HTTP status codes.
Every error page can be **overridden** by mounting a directory of custom pages into the container.

---

## Built-in pages

The following pages are included with AuthProxy and are served automatically when the corresponding
condition is detected:

| File name | Condition | HTTP status |
|-----------|-----------|-------------|
| `404.html` | The requested resource was not found. | 404 |
| `403.html` | The identity resolver denied access. | 403 |
| `tenant-not-found.html` | The resolved tenant does not exist in the platform (see [Tenant verification](tenancy.md#tenant-verification)). | 404 |
| `select-tenant.html` | Tenant selection is enabled and the authenticated user has not selected a tenant yet. The page reads the `.cratis-tenants` cookie to render selectable tenants. | 200 |
| `invitation-expired.html` | An invite link was followed but the JWT token has passed its expiry time. | 401 |
| `invitation-invalid.html` | An invite link was followed but the JWT token is malformed or has an invalid signature. | 401 |
| `invitation-select-provider.html` | A valid invite link was followed and multiple identity providers are configured. The page reads the `.cratis-providers` cookie to render a sign-in button for each available provider. | 200 |
| `invitation-subject-already-exists.html` | The authenticated user's subject is already associated with an existing account during invite exchange (Phase 2). | 409 |
| `invitation-email-unavailable.html` | Email binding is enabled, but the identity provider supplied no authenticated-session email address during invite exchange (Phase 2). | 403 |
| `invitation-email-mismatch.html` | Email binding is enabled, and the identity provider supplied another address or explicitly reported `email_verified=false` during invite exchange (Phase 2). | 403 |

---

## Overriding pages

Mount a directory into the container and point `Cratis:AuthProxy:PagesPath` at the mount path.
AuthProxy looks up each page by its conventional file name inside that directory.
Any page file that is present overrides the built-in default; missing files fall back to the built-in version.

```json
{
  "Cratis": {
    "AuthProxy": {
      "PagesPath": "/mnt/pages"
    }
  }
}
```

Equivalent environment variable:

```
Cratis__AuthProxy__PagesPath=/mnt/pages
```

### Container mount example (Docker Compose)

```yaml
services:
  authproxy:
    image: cratis/authproxy:latest
    volumes:
      - ./my-pages:/mnt/pages
    environment:
      Cratis__AuthProxy__PagesPath: /mnt/pages
```

### Page assets

Pages can reference stylesheets, images, and other assets.  
Place asset files in the same pages directory — they are served at the `/_pages/` URL prefix.

```html
<!-- inside your custom 404.html -->
<link rel="stylesheet" href="/_pages/styles.css" />
<img src="/_pages/logo.svg" alt="Logo" />
```

---

## Invitation error pages

Invitation error pages use **full descriptive names** rather than numeric HTTP status codes because
they represent application-level conditions, not generic HTTP errors.

### `invitation-expired.html`

Served when a user follows an `/invite/<token>` link whose JWT has a valid signature but has
passed its `exp` claim. The user should request a fresh invitation.

### `invitation-invalid.html`

Served when the token on an `/invite/<token>` link is malformed, carries an invalid signature,
or cannot be parsed at all. This typically indicates a truncated or otherwise corrupted link.

### `invitation-select-provider.html`

Served when a valid invite link is followed and **two or more** identity providers are configured.
Before serving the page, AuthProxy injects the `.cratis-providers` cookie (see below) so the page
can render a sign-in button for each available provider without an additional HTTP round-trip.

The built-in page reads the cookie with JavaScript and renders one sign-in button per provider.
You can override it with a custom branded version by placing your own `invitation-select-provider.html`
in the configured pages directory.

### `invitation-subject-already-exists.html`

Served during Phase 2 (post-login invite exchange) when the exchange endpoint returns HTTP 409 Conflict,
indicating that the authenticated user's subject is already associated with an existing account.
The user should sign in with their existing account rather than completing the invitation again.

If you prefer to redirect users to a custom URL instead of serving this page, configure
`Invite.SubjectAlreadyExistsUrl` (see [Invitation for Creating Organization](lobby/invitation-for-creating-organization.md#configuration)).

### `invitation-email-unavailable.html`

Served during Phase 2 when `Invite.EmailClaim` binds the invitation to an address but the identity provider
supplied no authenticated-session email address. This is not evidence that the invitee used the wrong account;
it means AuthProxy has no address to compare. Customize this page to help the user choose a provider or account
that exposes an address.

### `invitation-email-mismatch.html`

Served during Phase 2 when the provider supplied an address different from the invited address, or explicitly
reported `email_verified=false`. An absent `email_verified` claim is not universal proof of ownership and is
forwarded as `null`; OAuth providers do not currently map that claim. See
[Invitation to Organization](lobby/invitation-to-organization.md) for the complete binding behavior.

---

## Provider info cookie (`.cratis-providers`)

When AuthProxy serves the `invitation-select-provider.html` page it sets a short-lived, **non-HTTP-only**
cookie named `.cratis-providers`.  The cookie value is a URL-encoded JSON array where each element
describes one configured identity provider:

```json
[
  {
    "name": "Microsoft",
    "type": "Microsoft",
    "loginUrl": "/.cratis/login/microsoft"
  },
  {
    "name": "Google",
    "type": "Google",
    "loginUrl": "/.cratis/login/google"
  }
]
```

| Field | Description |
|-------|-------------|
| `name` | Display name of the provider (from `Authentication:OidcProviders[].Name`). |
| `type` | Provider type hint — `Microsoft`, `Google`, `GitHub`, `Apple`, or `Custom`. |
| `loginUrl` | AuthProxy-relative URL that initiates the OIDC/OAuth challenge for the provider. |

A custom `invitation-select-provider.html` page can read this cookie with JavaScript:

```javascript
function getCookie(name) {
    var match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
}

var providers = JSON.parse(getCookie('.cratis-providers') || '[]');
providers.forEach(function(provider) {
    var a = document.createElement('a');
    a.href = provider.loginUrl;
    a.textContent = 'Sign in with ' + provider.name;
    document.getElementById('providers').appendChild(a);
});
```

---

## Tenant not found

`tenant-not-found.html` is served when tenant verification is enabled and the platform reports
that the resolved tenant ID does not exist. See [Tenant verification](tenancy.md#tenant-verification)
for how to configure the verification endpoint.

---

## Tenant selection page

`select-tenant.html` is served when the `Selection` tenant-resolution strategy is configured and no
`.cratis-tenant` cookie is present for the authenticated user.

See [Tenant Selection Page](tenant-selection.md) for:

- `TenantsEndpoint` configuration
- `.cratis-tenants` cookie schema (`id`, `name`)
- `/.cratis/select-tenant` selection callback behavior
- full custom-page example
