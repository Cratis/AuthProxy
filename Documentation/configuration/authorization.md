# Authorization

Authentication tells you *who* is knocking. On a public host that is not the same as deciding whether they
may come in.

Put AuthProxy on the internet with GitHub sign-in and the sign-in works — for everybody. Every GitHub
account on earth is a real, verified identity, so every one of them completes the handshake and lands on
your application. The application is now responsible for turning away people it has never heard of, on
every endpoint, forever, and the first mistake is a stranger inside.

`Cratis:AuthProxy:Authorization` makes the proxy the **first gate**: an authenticated caller who does not
carry what you require never reaches a service at all.

It is off unless you turn it on. Declare nothing and AuthProxy behaves exactly as it always has.

---

## Declaring a requirement

A requirement names a claim, and optionally the values you accept:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authorization": {
        "RequiredClaims": [
          { "Claim": "urn:github:organization", "AnyOf": [ "Cratis" ] }
        ]
      }
    }
  }
}
```

An authenticated caller carrying `urn:github:organization` with the value `Cratis` gets through. Anyone
else — signed in or not, and no matter which provider signed them in — is answered with the
[not-authorized page](#what-a-refused-caller-sees) and goes no further.

Leave `AnyOf` out to require only that the claim is **present**:

```json
{ "Claim": "urn:example:entitlement" }
```

That is the right shape when the identity provider already emits the claim only for the people who should
get in, and enumerating the acceptable values in the proxy would mean restating — and then maintaining — a
decision the provider has already made.

Values are compared **case-insensitively**, and surrounding whitespace is trimmed. Organization names, team
slugs and role names are case-insensitive in the systems they come from, and `Cratis` versus `cratis` is not
a distinction worth locking a deployment out over.

---

## All of the claims, any of the values

Two axes, and they compose in opposite directions. Say them out loud before you write them:

| | Means | Reads as |
|---|---|---|
| Several entries in `RequiredClaims` | **All** must be satisfied | *and* |
| Several values in one entry's `AnyOf` | **Any one** satisfies it | *or* |

So "in the `Cratis` organization **and** on the `planner` team" is two entries:

```json
"RequiredClaims": [
  { "Claim": "urn:github:organization", "AnyOf": [ "Cratis" ] },
  { "Claim": "urn:github:team", "AnyOf": [ "Cratis/planner" ] }
]
```

…while "on **either** of these two teams" is one entry with two values:

```json
"RequiredClaims": [
  { "Claim": "urn:github:team", "AnyOf": [ "Cratis/planner", "Cratis/operations" ] }
]
```

The distinction matters because the wrong reading fails in the dangerous direction. If entries were an
*or*, adding a team requirement next to an organization requirement would **widen** access — to anyone in
the organization *or* on that team in any organization — which is the opposite of what you meant by adding
it.

> [!IMPORTANT]
> A requirement whose `Claim` is blank refuses to start. It could never be satisfied, so applying it
> would refuse every caller, and dropping it would silently leave the gate open. AuthProxy fails at
> startup instead, naming the exact configuration key — which is the one moment somebody is watching.

---

## Narrowing one service

The same section on a service applies to requests routed to that service, **in addition to** whatever the
root requires:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authorization": {
        "RequiredClaims": [
          { "Claim": "urn:github:organization", "AnyOf": [ "Cratis" ] }
        ]
      },
      "Services": {
        "portal": {
          "Frontend": { "BaseUrl": "http://portal-web:3000/" },
          "Backend": { "BaseUrl": "http://portal:8080/" }
        },
        "admin": {
          "Frontend": { "BaseUrl": "http://admin-web:3000/" },
          "Authorization": {
            "RequiredClaims": [
              { "Claim": "urn:github:team", "AnyOf": [ "Cratis/operations" ] }
            ]
          }
        }
      }
    }
  }
}
```

Everyone reaching either service is in the `Cratis` organization; only the operations team reaches `admin`.

A service can therefore **narrow** who reaches it, never widen it. The alternative — a service section
replacing the root's — would turn the root into a default rather than a floor, so a section written to add
an extra check would quietly drop the organization check, and a service added later with no section at all
would be the way in.

Which service a request targets is worked out the same way the [route table](services.md) works it out: the
single configured service when there is only one, otherwise the `Service-ID` header or the `service` query
parameter. A request in a multi-service deployment that names neither reaches no service route either, so
only the root requirements apply to it.

---

## GitHub organizations and teams

This is the case the feature was built for, and it needs one extra thing.

GitHub's user endpoint — `https://api.github.com/user`, the one you configure as
`UserInformationEndpoint` — returns a profile and **nothing about membership**. There is no organization
field to map to a claim, so no amount of `ClaimMappings` produces one. Membership lives behind
`/user/orgs` and `/user/teams`, and reading those requires the `read:org` scope.

**Ask for `read:org` and AuthProxy fetches it for you**, once, while the sign-in completes, and adds it to
the session as claims:

| Claim | Value | Example |
|-------|-------|---------|
| `urn:github:organization` | The organization's GitHub login | `Cratis` |
| `urn:github:team` | `organization/team-slug` | `Cratis/planner` |

One claim per organization and one per team. The team slug is the name in the team's URL —
`github.com/orgs/Cratis/teams/planner` is the slug `planner`. It is qualified by its organization because
a slug is only unique within one: two organizations may both have a `developers` team, and an unqualified
claim would let membership of either satisfy a requirement written for one.

The scope **is** the opt-in. There is no second switch to forget, and no way for the two to disagree.
Without `read:org` nothing extra is requested, no extra call is made, and sign-in is exactly what it was.

Here is a complete configuration restricting a host to the `planner` team in the `Cratis` organization:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "OAuthProviders": [
          {
            "Name": "GitHub",
            "Type": "GitHub",
            "AuthorizationEndpoint": "https://github.com/login/oauth/authorize",
            "TokenEndpoint": "https://github.com/login/oauth/access_token",
            "UserInformationEndpoint": "https://api.github.com/user",
            "ClientId": "<client-id>",
            "ClientSecret": "<client-secret>",
            "Scopes": [ "read:user", "user:email", "read:org" ],
            "ClaimMappings": {
              "sub": "id",
              "name": "name",
              "preferred_username": "login",
              "email": "email"
            }
          }
        ]
      },
      "Authorization": {
        "RequiredClaims": [
          { "Claim": "urn:github:organization", "AnyOf": [ "Cratis" ] },
          { "Claim": "urn:github:team", "AnyOf": [ "Cratis/planner" ] }
        ]
      }
    }
  }
}
```

A few things worth knowing before you deploy it:

- **The claims are added at sign-in, not per request.** They live in the authentication cookie, so
  membership revoked at GitHub takes effect when the session ends — bound by
  `Cratis:AuthProxy:Session:Lifetime`, twelve hours by default. Shorten it if you need revocation to bite
  sooner.
- **The application gets them too.** They travel on the forwarded `x-ms-client-principal` header like every
  other claim, so your service can read organization and team membership without ever calling GitHub.
- **A failed read never breaks the sign-in.** If GitHub is unreachable, or the token lacks the scope, the
  claims are simply absent — which the gate then refuses, with an explanation. That is the closed
  direction, reached gently.
- **Membership is read in pages of 100, up to five pages.** Well past any plausible allow-list, and the
  bound keeps a sign-in someone is waiting on from turning into an unbounded crawl.
- **`Type` must be `GitHub`.** It is what selects the logo on the provider-selection page, and what tells
  AuthProxy these endpoints are GitHub's.

GitHub Enterprise works without further configuration: the membership endpoints are derived from whatever
`UserInformationEndpoint` you configured, so `https://github.example.com/api/v3/user` resolves its own
`/user/orgs` and `/user/teams`.

---

## What a refused caller sees

The [`not-authorized.html`](well-known-pages.md) page, at `403`, with a **Sign out** link.

Both halves are deliberate. A redirect back to the identity provider — the reflex for "not allowed" — is
wrong here: the caller *is* signed in, so they would sign in again as the same person and loop forever. And
`403` is a status a `fetch()` or a command-line client can act on, so browsers and non-browsers get the same
honest answer.

The sign-out link matters because it is the only way forward. Someone who signed in with a personal account
by mistake is otherwise stuck looking at a page that will not change. Override the page — brand it, tell
people who to ask for access — by mounting a pages directory; see [Well-Known Pages](well-known-pages.md).

Every refusal is logged at warning level with the claim that was not satisfied and the path that was
requested. The claim **type** only — never the value the caller carried, which would put an identity in the
log to record that it was turned away.

---

## What is never gated

Three things pass through untouched, and each for a reason worth knowing:

- **Callers with no session.** They are refused — or sent to sign in — by the machinery that already does
  that. This gate is about who a signed-in caller *is*, not whether there is one.
- **The authentication endpoints themselves** — `/.cratis/providers`, `/.cratis/login/{scheme}`, the
  provider callbacks, `/.cratis/logout` and the `/_pages` assets. Gating the only route to acquiring the
  claims on already having them is a door locked from the inside.
- **Paths a service declares in [`AnonymousPaths`](public-surfaces.md).** This is the one that surprises
  people, so be clear about it: a declared path exists precisely for callers with **no session** — a
  webhook receiver, a magic-link landing page — and a caller with no session carries no claims to satisfy
  anything with. Gating them would refuse every one of them, and a payment provider posting a webhook would
  get a `403` it can do nothing about. A declared anonymous path is public; requiring a claim somewhere else
  does not quietly un-declare it.

> [!NOTE]
> That last point cuts both ways. If a path is declared anonymous, this gate will not protect it — so
> declare the narrowest prefix that works, and let the application authorize what it serves there.

---

## Environment variables

Everything above is settable purely through environment variables, which is how AuthProxy is normally
deployed. Array entries are indexed:

```bash
Cratis__AuthProxy__Authorization__RequiredClaims__0__Claim=urn:github:organization
Cratis__AuthProxy__Authorization__RequiredClaims__0__AnyOf__0=Cratis
Cratis__AuthProxy__Authorization__RequiredClaims__1__Claim=urn:github:team
Cratis__AuthProxy__Authorization__RequiredClaims__1__AnyOf__0=Cratis/planner
```

Per service, the same list moves under the service key:

```bash
Cratis__AuthProxy__Services__admin__Authorization__RequiredClaims__0__Claim=urn:github:team
Cratis__AuthProxy__Services__admin__Authorization__RequiredClaims__0__AnyOf__0=Cratis/operations
```

Indices must start at `0` and not skip — a gap truncates the list where the gap is, silently dropping every
requirement after it.

From a .NET Aspire app host, the same thing is expressed as builder calls:

```csharp
builder.AddAuthProxy("authproxy")
    .WithRequiredClaim("urn:github:organization", "Cratis")
    .WithRequiredClaim("urn:github:team", "Cratis/planner")
    .WithRequiredClaimForService("admin", "urn:github:team", "Cratis/operations");
```

Repeated calls append, so requirements can be declared wherever they belong in the app host rather than all
in one place.

---

## Settings reference

| Property | Type | Description |
|----------|------|-------------|
| `Authorization.RequiredClaims` | `ClaimRequirement[]` | Requirements every authenticated caller must satisfy. **All** of them must hold. Empty (the default) authorizes nobody away — the proxy authenticates without authorizing. |
| `Authorization.RequiredClaims[].Claim` | `string` | The claim type the caller must carry. Blank fails startup. |
| `Authorization.RequiredClaims[].AnyOf` | `string[]` | Values that satisfy the requirement, compared case-insensitively. Empty requires only that the claim is present. |
| `Services.<key>.Authorization` | `Authorization` | The same shape, applied to requests routed to that service **in addition to** the root's. |

---

## Checking it works

Sign in with an account that qualifies and one that does not. The second should land on the not-authorized
page at `403`, and nothing should reach your backend — no request, and no `/.cratis/me` identity call
either, because the refusal happens before both.

If a qualifying account is also refused, the requirement and the claim disagree. Read the warning in the
proxy's log: it names the claim that was not satisfied. For GitHub, the usual causes are the `read:org`
scope missing from `Scopes`, a team named by its display name rather than its URL slug, or a team written
without its `organization/` prefix.

If *nobody* is refused, no requirement bound at all. Check the indices in the environment variables — a
skipped index truncates the list.

Next: [Public Application Surfaces](public-surfaces.md) for the paths this gate deliberately leaves open,
and [Authentication](authentication.md) for the providers it gates.
