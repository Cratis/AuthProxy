# Well-Known Pages

Ingress serves built-in HTML pages for a range of conditions — provider selection,
invitation errors, tenant errors, and generic HTTP errors.
Every page can be **overridden** by mounting a directory of custom pages into the container.

---

## Built-in pages

The following pages are included with Ingress and are served automatically when the corresponding
condition is detected:

| File name | Condition | HTTP status |
|-----------|-----------|-------------|
| `404.html` | The requested resource was not found. | 404 |
| `403.html` | The identity resolver denied access. | 403 |
| `tenant-not-found.html` | The resolved tenant does not exist in the platform (see [Tenant verification](tenancy.md#tenant-verification)). | 404 |
| `select-provider.html` | A protected resource was requested and multiple identity providers are configured. The page reads the `.cratis-providers` cookie to render a sign-in button for each available provider. | 200 |
| `invitation-expired.html` | An invite link was followed but the JWT token has passed its expiry time. | 401 |
| `invitation-invalid.html` | An invite link was followed but the JWT token is malformed or has an invalid signature. | 401 |
| `invitation-select-provider.html` | A valid invite link was followed and multiple identity providers are configured. The page reads the `.cratis-providers` cookie to render a sign-in button for each available provider. | 200 |
| `invitation-subject-already-exists.html` | The authenticated user's subject is already associated with an existing account during invite exchange (Phase 2). | 409 |

---

## Overriding pages

Mount a directory into the container and point `Ingress:PagesPath` at the mount path.
Ingress looks up each page by its conventional file name inside that directory.
Any page file that is present overrides the built-in default; missing files fall back to the built-in version.

```json
{
  "Ingress": {
    "PagesPath": "/mnt/pages"
  }
}
```

Equivalent environment variable:

```
Ingress__PagesPath=/mnt/pages
```

### Container mount example (Docker Compose)

```yaml
services:
  ingress:
    image: cratis/ingress:latest
    volumes:
      - ./my-pages:/mnt/pages
    environment:
      Ingress__PagesPath: /mnt/pages
```

### Page assets

Pages can reference stylesheets, images, and other assets.  
Place asset files in the same pages directory — they are served at the `/_pages/` URL prefix.

```html
<!-- inside your custom page -->
<link rel="stylesheet" href="/_pages/styles.css" />
<img src="/_pages/logo.svg" alt="Logo" />
```

---

## Provider selection pages

`select-provider.html` and `invitation-select-provider.html` both serve the same purpose —
letting the user choose an identity provider when multiple are configured — but they are
triggered by different flows:

| Page | Triggered by |
|------|-------------|
| `select-provider.html` | Direct navigation to a protected resource when not yet authenticated. |
| `invitation-select-provider.html` | Following a valid invite link. |

Both pages receive provider data via the `.cratis-providers` cookie and work identically
from a customization standpoint.  See [Provider Selection Pages](invitation-provider-selection.md)
for the full cookie schema, JavaScript examples, and guidance on building a custom branded page.

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

### `invitation-subject-already-exists.html`

Served during Phase 2 (post-login invite exchange) when the exchange endpoint returns HTTP 409 Conflict,
indicating that the authenticated user's subject is already associated with an existing account.

---

## Tenant not found

`tenant-not-found.html` is served when tenant verification is enabled and the platform reports
that the resolved tenant ID does not exist. See [Tenant verification](tenancy.md#tenant-verification)
for how to configure the verification endpoint.
