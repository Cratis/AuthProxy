# Tenant Selection Page

When tenant selection is configured, AuthProxy serves a tenant-selection page after login until the
user chooses a tenant.

The page receives tenant data through a cookie, not by calling your tenant endpoint directly.

---

## Flow

1. Authenticated request arrives without a `.cratis-tenant` cookie.
2. AuthProxy calls the configured `Selection.Options.TenantsEndpoint`.
3. AuthProxy writes `.cratis-tenants` (URL-encoded JSON array) and serves `select-tenant.html`.
4. User clicks a tenant option.
5. Browser navigates to `/.cratis/select-tenant?tenantId=<id>&returnUrl=<path>`.
6. AuthProxy validates the selected `tenantId` against `TenantsEndpoint` and sets `.cratis-tenant`.
7. AuthProxy redirects back to `returnUrl`.

---

## Endpoint response shape

`TenantsEndpoint` must return JSON with one object per selectable tenant:

```json
[
  {
    "id": "some string",
    "name": "some string"
  }
]
```

---

## Cookie shape used by the page

AuthProxy writes `.cratis-tenants` with the same shape:

```json
[
  {
    "id": "studio",
    "name": "Cratis Studio"
  },
  {
    "id": "sales",
    "name": "Sales Portal"
  }
]
```

---

## Building a custom `select-tenant.html`

`select-tenant.html` is a normal overridable page in `PagesPath`, exactly like the other built-in pages.

Minimum requirements:

1. Read `.cratis-tenants` from `document.cookie`.
2. Parse JSON and render `name`.
3. Link each item to `/.cratis/select-tenant?tenantId=<id>&returnUrl=<current path>`.

Example:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Select tenant</title>
</head>
<body>
  <h1>Select tenant</h1>
  <ul id="tenants"></ul>
  <p id="error" hidden>Unable to load tenant options.</p>

  <script>
    (function () {
      function getCookie(name) {
        var pattern = new RegExp('(?:^|; )' +
          name.replace(/([.*+?^=!:${}()|[\]\/\\])/g, '\\$1') + '=([^;]*)');
        var match = document.cookie.match(pattern);
        return match ? decodeURIComponent(match[1]) : null;
      }

      var json = getCookie('.cratis-tenants');
      var tenants;
      try { tenants = JSON.parse(json); } catch (_) { tenants = null; }

      if (!tenants || tenants.length === 0) {
        document.getElementById('error').hidden = false;
        return;
      }

      var returnUrl = window.location.pathname + window.location.search;
      var list = document.getElementById('tenants');

      tenants.forEach(function (tenant) {
        var li = document.createElement('li');
        var a  = document.createElement('a');
        a.href = '/.cratis/select-tenant?tenantId=' +
          encodeURIComponent(tenant.id) +
          '&returnUrl=' + encodeURIComponent(returnUrl);
        a.textContent = tenant.name;
        li.appendChild(a);
        list.appendChild(li);
      });
    }());
  </script>
</body>
</html>
```
