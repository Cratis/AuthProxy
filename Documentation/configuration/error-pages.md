# Custom Error Pages

Ingress serves user-friendly HTML pages for error conditions instead of bare HTTP status codes.
Every error page can be **overridden** by mounting a directory of custom pages into the container.

---

## Built-in pages

The following pages are included with Ingress and are served automatically when the corresponding
condition is detected:

| File name | Condition | HTTP status |
|-----------|-----------|-------------|
| `404.html` | The requested resource was not found. | 404 |
| `403.html` | The identity resolver denied access. | 403 |
| `tenant-not-found.html` | The resolved tenant does not exist in the platform (see [Tenant verification](tenancy.md#tenant-verification)). | 404 |
| `invitation-expired.html` | An invite link was followed but the JWT token has passed its expiry time. | 401 |
| `invitation-invalid.html` | An invite link was followed but the JWT token is malformed or has an invalid signature. | 401 |

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

---

## Tenant not found

`tenant-not-found.html` is served when tenant verification is enabled and the platform reports
that the resolved tenant ID does not exist. See [Tenant verification](tenancy.md#tenant-verification)
for how to configure the verification endpoint.
