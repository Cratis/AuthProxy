# Provider Selection Pages

When multiple identity providers are configured, Ingress serves a provider-selection page
so the user can choose which provider to sign in with.  Two pages serve this role depending
on the flow that triggered them:

| Page | Triggered by |
| ---- | ------------ |
| `select-provider.html` | Direct navigation to a protected resource when not yet authenticated. |
| `invitation-select-provider.html` | Following a valid invite link. |

Both pages work identically — they receive provider data via the `.cratis-providers` cookie
and can be overridden in the same way.  The built-in versions are functional but minimally
styled.  This guide explains how to replace either or both with fully branded custom pages.

---

## How Ingress injects provider data

Before serving either page, Ingress sets a short-lived, **non-HTTP-only** cookie named
`.cratis-providers`.  The value is a URL-encoded JSON array — one entry per configured
identity provider:

```json
[
  {
    "name": "Contoso AD",
    "type": "Microsoft",
    "loginUrl": "/.cratis/login/contoso-ad"
  },
  {
    "name": "GitHub",
    "type": "GitHub",
    "loginUrl": "/.cratis/login/github"
  }
]
```

### Cookie fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Human-readable display name taken from `Authentication:OidcProviders[].Name`. |
| `type` | `string` | Provider brand — `Microsoft`, `Google`, `GitHub`, `Apple`, or `Custom`. Use this to pick logos or apply brand-specific styling. |
| `loginUrl` | `string` | Ingress-relative URL that initiates the OIDC/OAuth challenge for this provider. Navigating to this URL starts the login flow and, after a successful login, redirects the user back to the original destination. |

The cookie expires after 15 minutes and is deleted automatically by the browser after that time.

---

## Reading the cookie

The cookie is not HTTP-only so your page's JavaScript can access it directly via
`document.cookie`.  The value is URL-encoded, so decode it before parsing:

```javascript
/**
 * Returns the decoded value of the named cookie, or null if it is not present.
 */
function getCookie(name) {
    var pattern = new RegExp('(?:^|; )' +
        name.replace(/([.*+?^=!:${}()|[\]\/\\])/g, '\\$1') + '=([^;]*)');
    var match = document.cookie.match(pattern);
    return match ? decodeURIComponent(match[1]) : null;
}

var providersJson = getCookie('.cratis-providers');
var providers = providersJson ? JSON.parse(providersJson) : [];
```

---

## Minimum viable custom page

A custom page only needs to:

1. Read the `.cratis-providers` cookie.
2. Render a clickable sign-in element whose `href` is the provider's `loginUrl`.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sign In</title>
  <link rel="stylesheet" href="/_pages/brand.css" />
</head>
<body>
  <main id="content">
    <h1>Choose how you want to sign in</h1>
    <ul id="providers"></ul>
    <p id="error" hidden>
      Unable to load sign-in options.
      Please try again or contact support.
    </p>
  </main>

  <script>
    (function () {
      function getCookie(name) {
        var pattern = new RegExp('(?:^|; )' +
          name.replace(/([.*+?^=!:${}()|[\]\/\\])/g, '\\$1') + '=([^;]*)');
        var match = document.cookie.match(pattern);
        return match ? decodeURIComponent(match[1]) : null;
      }

      var json = getCookie('.cratis-providers');
      var providers;

      try { providers = JSON.parse(json); } catch (_) { providers = null; }

      if (!providers || providers.length === 0) {
        document.getElementById('error').hidden = false;
        return;
      }

      var list = document.getElementById('providers');
      providers.forEach(function (provider) {
        var li = document.createElement('li');
        var a  = document.createElement('a');
        a.href        = provider.loginUrl;
        a.textContent = 'Sign in with ' + provider.name;
        a.className   = 'provider-btn provider-btn--' + provider.type.toLowerCase();
        li.appendChild(a);
        list.appendChild(li);
      });
    }());
  </script>
</body>
</html>
```

> **Note:** Assets placed in the same pages directory are served at the `/_pages/` URL prefix.
> The `brand.css` reference above assumes `brand.css` lives alongside your custom page.

The same HTML template works for both `select-provider.html` and `invitation-select-provider.html`.
You can use identical files, or tailor each one — for example, showing "You have been invited" in
the invitation variant and "Sign in to continue" in the direct-access variant.

---

## Deploying custom pages

1. Create the HTML file(s) named exactly `select-provider.html` and/or `invitation-select-provider.html`.
2. Place any CSS, images, or other assets in the same directory.
3. Mount the directory into your container and point `Ingress:PagesPath` at the mount path:

```yaml
# docker-compose.yml
services:
  ingress:
    image: cratis/ingress:latest
    volumes:
      - ./my-pages:/mnt/pages
    environment:
      Ingress__PagesPath: /mnt/pages
```

Ingress resolves each page file by name — if a file exists in the configured `PagesPath` it is
used; otherwise the built-in default is served.

---

## Using the `type` field for branded buttons

The `type` value maps to the `OidcProviderType` enum.  Use it to apply provider-specific logos
or colors:

```javascript
var LOGOS = {
  Microsoft: '/_pages/icons/microsoft.svg',
  Google:    '/_pages/icons/google.svg',
  GitHub:    '/_pages/icons/github.svg',
  Apple:     '/_pages/icons/apple.svg',
  Custom:    '/_pages/icons/generic.svg'
};

providers.forEach(function (provider) {
  var a   = document.createElement('a');
  a.href  = provider.loginUrl;

  var img    = document.createElement('img');
  img.src    = LOGOS[provider.type] || LOGOS.Custom;
  img.alt    = provider.name;
  img.width  = 20;
  img.height = 20;

  a.appendChild(img);
  a.appendChild(document.createTextNode(' Sign in with ' + provider.name));
  document.getElementById('providers').appendChild(a);
});
```

---

## Complete flow reference

### Direct access flow (`select-provider.html`)

```
User navigates to protected resource
        │
        ▼
Unauthenticated request detected
        │
        ├─ Single provider ──► redirect to /.cratis/login/<scheme>
        │
        └─ Multiple providers
                │
                ▼
  Set .cratis-providers cookie
  Serve select-provider.html
                │
                │ User clicks provider
                ▼
  GET /.cratis/login/<scheme>
                │
                ▼
      OIDC/OAuth challenge
                │
                ▼
      Redirect to original resource
```

### Invitation flow (`invitation-select-provider.html`)

```
User clicks invite link
        │
        ▼
GET /invite/<token>
        │
        ├─ Token invalid/expired ──► invitation-invalid.html / invitation-expired.html
        │
        └─ Token valid
                │
                ├─ Single provider ──► redirect to /.cratis/login/<scheme>
                │
                └─ Multiple providers
                        │
                        ▼
          Set .cratis-providers cookie
          Serve invitation-select-provider.html
                        │
                        │ User clicks provider
                        ▼
          GET /.cratis/login/<scheme>
                        │
                        ▼
              OIDC/OAuth challenge
                        │
                        ▼
              POST-login exchange
                        │
                        ▼
              Redirect to lobby / application
```
