---
title: "gRPC Services"
description: "Forward gRPC calls through AuthProxy to a gRPC backend, from an ingress that terminates TLS, beside the application a person signs in to."
---

# gRPC Services

AuthProxy can forward gRPC: a long-lived stream from an agent or a daemon, say, beside the web application people
sign in to on the same host. Three settings make that work, and each solves a separate problem:

| Setting | Problem it solves |
|---|---|
| [`GrpcListener`](#the-grpc-listener) | Behind an ingress that terminates TLS, gRPC reaches the proxy as plain-text HTTP/2. A plain-text listener negotiates nothing, so it has to speak HTTP/2 only. |
| [`Backend.Protocol: Http2`](#forwarding-over-http2) | AuthProxy forwards to a plain-HTTP backend over HTTP/1.1 unless it is told otherwise, and HTTP/1.1 cannot carry gRPC's streams or trailers. |
| [`Default`](#keeping-the-application-the-default) | Declaring a second service takes the catch-all routes away from the first. `Default` keeps them. |

---

## A worked example

An application served at `app.example.com`, whose backend also hosts a gRPC service, `acme.agents.Agent`, on a
second port that speaks HTTP/2 only:

```json
{
  "Cratis": {
    "AuthProxy": {
      "GrpcListener": { "Port": 8082 },
      "Services": {
        "app": {
          "Default": true,
          "Backend": { "BaseUrl": "http://app/" },
          "Frontend": { "BaseUrl": "http://app/" }
        },
        "agents": {
          "PathPrefix": "/acme.agents.Agent",
          "Backend": { "BaseUrl": "http://app:8082/", "Protocol": "Http2" },
          "AnonymousPaths": [ "/acme.agents.Agent" ],
          "ResolveIdentityDetails": false,
          "ActivityTimeout": "00:02:00"
        }
      }
    }
  }
}
```

A gRPC call's path is `/<package>.<Service>/<Method>`, so the service name is the path prefix. Put every method a
client calls in one gRPC service and one prefix covers them.

The ingress hands the prefix to the gRPC listener on its own Ingress object, because ingress-nginx sets the backend
protocol per Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-grpc
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: GRPC
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
spec:
  ingressClassName: nginx
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /acme.agents.Agent
            pathType: Prefix
            backend:
              service:
                name: authproxy
                port:
                  number: 8082
```

---

## The gRPC listener

```json
"GrpcListener": { "Port": 8082, "BindAddress": "*" }
```

`GrpcListener` opens one more listener, which speaks HTTP/2 only and no HTTP/1.1. It runs the same pipeline as the
public listener: authentication, tenancy, anonymous paths and forwarding all apply, and identity headers a caller
sends are stripped. Leave the section unset and no socket is opened.

- `Port` is required and must differ from the public listener's port and from the
  [management listener](management-listener.md)'s. AuthProxy refuses to start otherwise.
- `BindAddress` defaults to every address, because the ingress reaches it from outside the pod.
- On this listener, a gRPC call (`content-type: application/grpc...`) has no request body limit. A streaming call's
  request body is every message the client sends while the call is open, so a limit on its total size would end a
  long-lived stream in the middle. The gRPC service bounds each message itself.

## Forwarding over HTTP/2

```json
"Backend": { "BaseUrl": "http://app:8082/", "Protocol": "Http2" }
```

`Protocol` decides the HTTP version AuthProxy forwards to an endpoint with. `Default` uses HTTP/2 where the endpoint
negotiates it over TLS and HTTP/1.1 otherwise. `Http2` demands HTTP/2 also over plain HTTP. A gRPC backend needs
`Http2`. The setting covers requests AuthProxy forwards; its own calls to the service, such as identity details and
registration, are unaffected.

The backend's listener must speak HTTP/2 only, for the same reason the gRPC listener does. In ASP.NET Core that is an
endpoint with `Protocols = HttpProtocols.Http2`.

## Keeping the application the default

A deployment with one service, declaring neither `Hosts` nor a `PathPrefix`, reaches that service through plain
catch-all routes. A second service, even one under its own prefix, ends that: every service is then reached only
through its hosts, its prefix or a [selection header](services.md#routing-by-host-or-path-prefix).

`"Default": true` keeps the catch-all routes on the service that sets it. The prefix still wins on its own paths,
because a prefix route is ordered ahead of the catch-all. At most one service may set `Default`, and it declares
neither hosts nor a prefix; AuthProxy refuses to start otherwise.

## Authenticating the caller

A gRPC client is rarely a person with a browser session. Declaring the prefix in `AnonymousPaths` stops AuthProxy
demanding one, and the service authenticates each call itself, typically by a bearer token in the `authorization`
metadata. A request without a session keeps the `Authorization` header it arrived with
(see `CallerAuthorizationHeader` in [Services](services.md)), so the token reaches the backend.

`ResolveIdentityDetails: false` keeps AuthProxy from asking the gRPC backend about signed-in people, which a listener
serving only gRPC does not answer.

## Long-lived calls

A stream with long quiet stretches is closed by whichever hop gives up first:

- AuthProxy's `ActivityTimeout` (on the service or endpoint) counts the time since data last moved in either
  direction. Have the client send something more often than this, or raise it.
- ingress-nginx's `proxy-read-timeout` and `proxy-send-timeout` also apply to gRPC.
- HTTP/2 keep-alive pings from the client keep idle connections from being dropped by load balancers in between.
