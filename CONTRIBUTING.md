# Contributing to AuthProxy

Build and test with `dotnet build` and `dotnet test` from the repository root. Pull requests are released by label: the description is published verbatim as the release note, following [the pull request template](https://github.com/Cratis/AuthProxy/blob/main/.github/pull_request_template.md).

## Breaking release notes for path, forwarding and credential changes

AuthProxy sits in front of all traffic to the applications behind it. A change to which requests it serves, forwards or refuses can break those applications without warning: their health checks stay green while real traffic fails. The release note is the only warning someone upgrading gets, so it has to say so.

A pull request is a **path or credential change** when it changes any of the following:

- which paths AuthProxy serves itself, forwards to a backend, or refuses, including `/.cratis/*`, routing, path matching, and prefix or casing rules
- the response a request gets, for example 200 becoming 401, 403 or 404, or a redirect appearing or disappearing
- which credential, provider or authentication scheme is selected for a request
- how credentials, sessions, cookies, tokens or forwarded identity headers are read, issued, stripped or forwarded

Every such change gets a release-note bullet, whatever the release label:

- Put the bullet under `## Changed`, `## Removed` or `## Security` and start it with `**Breaking:**`.
- Name who is affected, for example "applications using Arc live queries" or "backends that serve their own `/.cratis` endpoints".
- Say how someone can check whether they are affected: a concrete request and the response it now gets, or the configuration that changes the behavior.
- Choose the release label from the effect on the applications behind the proxy. When something they rely on stops working, the change is `major`. When the change is a fix that restores the intended behavior, say so in the bullet and keep the `**Breaking:**` marking.

For example:

```markdown
## Changed

- **Breaking:** Unmatched `/.cratis/*` paths are refused with 404 instead of being forwarded. Applications whose backend serves `/.cratis` endpoints, such as Arc queries and commands, are affected; to check, request `/.cratis/queries/health` through the proxy and look for a 404. (#123)
```
