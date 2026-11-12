# Consumer E2E lane

Builds the AuthProxy image from this working tree, runs a minimal real Arc app behind it, and drives
Arc's `/.cratis` surface from outside with a client-credentials bearer token: the refused unauthenticated
stream, the token exchange, an observable query over SSE and over WebSocket.

```shell
bash E2E/run.sh
```

Needs docker and the .NET SDK (10 and 11). CI runs the same script (`.github/workflows/consumer-e2e.yml`).

Bearer tokens are scoped to the service's client-credentials route prefix, which this lane sets to
`/.cratis`. The bearer path does not exercise `/.cratis/me`; the cookie-session paths are covered by the
`for_ArcCratisPaths` specs in `AuthProxy.Security.Specs`.
