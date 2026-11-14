#!/usr/bin/env bash
# Copyright (c) Cratis. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.
#
# Consumer lane: builds the AuthProxy image from this working tree, runs a real minimal Arc app behind it and
# drives it from outside (E2E/Client). Same entry point for CI and developers. Needs docker and the .NET SDK.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
logs="${E2E_LOG_DIR:-$root/.ai-work/e2e}"
mkdir -p "$logs"
export AUTHPROXY_IMAGE="${AUTHPROXY_IMAGE:-authproxy-e2e:local}"
# A run owns only its own containers, network and volumes, including on failure.
compose=(docker compose -p "authproxy-e2e-$$" -f E2E/docker-compose.yml)
umask 077
export OAUTH_GRANT_RUNTIME
OAUTH_GRANT_RUNTIME=$(mktemp -d "$logs/runtime.XXXXXX")
# Keep compose cleanup usable even if certificate generation fails before the key is written.
: > "$OAUTH_GRANT_RUNTIME/signing.conf"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "E2E failed (exit $status); container logs saved to $logs"
    "${compose[@]}" logs --no-color > "$logs/compose.log" 2>&1 || true
    tail -n 60 "$logs/compose.log" || true
  fi
  if "${compose[@]}" down -v --remove-orphans > /dev/null 2>&1; then
    # Only this run's explicit throwaway outputs; no work records or shared directories are removed.
    rm -f "$OAUTH_GRANT_RUNTIME/ca.key" "$OAUTH_GRANT_RUNTIME/ca.crt" "$OAUTH_GRANT_RUNTIME/ca.srl" \
      "$OAUTH_GRANT_RUNTIME/issuer.key" "$OAUTH_GRANT_RUNTIME/issuer.csr" "$OAUTH_GRANT_RUNTIME/issuer.crt" \
      "$OAUTH_GRANT_RUNTIME/issuer.ext" "$OAUTH_GRANT_RUNTIME/signing.pem" "$OAUTH_GRANT_RUNTIME/signing.der" \
      "$OAUTH_GRANT_RUNTIME/public.pem" "$OAUTH_GRANT_RUNTIME/signing.conf"
    rmdir "$OAUTH_GRANT_RUNTIME"
  else
    echo "Container cleanup failed; runtime files retained at $OAUTH_GRANT_RUNTIME; remove only after containers stop."
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "== Generating run-local TLS trust and envelope signing keys"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OAUTH_GRANT_RUNTIME/ca.key"
openssl req -new -x509 -key "$OAUTH_GRANT_RUNTIME/ca.key" -out "$OAUTH_GRANT_RUNTIME/ca.crt" -days 1 -subj /CN=AuthProxy-E2E-Throwaway-CA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OAUTH_GRANT_RUNTIME/issuer.key"
openssl req -new -key "$OAUTH_GRANT_RUNTIME/issuer.key" -out "$OAUTH_GRANT_RUNTIME/issuer.csr" -subj /CN=issuer
printf 'subjectAltName=DNS:issuer\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > "$OAUTH_GRANT_RUNTIME/issuer.ext"
openssl x509 -req -in "$OAUTH_GRANT_RUNTIME/issuer.csr" -CA "$OAUTH_GRANT_RUNTIME/ca.crt" -CAkey "$OAUTH_GRANT_RUNTIME/ca.key" -CAcreateserial -CAserial "$OAUTH_GRANT_RUNTIME/ca.srl" -out "$OAUTH_GRANT_RUNTIME/issuer.crt" -days 1 -extfile "$OAUTH_GRANT_RUNTIME/issuer.ext"
openssl verify -CAfile "$OAUTH_GRANT_RUNTIME/ca.crt" -verify_hostname issuer "$OAUTH_GRANT_RUNTIME/issuer.crt"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OAUTH_GRANT_RUNTIME/signing.pem"
openssl pkcs8 -topk8 -nocrypt -in "$OAUTH_GRANT_RUNTIME/signing.pem" -outform DER -out "$OAUTH_GRANT_RUNTIME/signing.der"
openssl pkey -in "$OAUTH_GRANT_RUNTIME/signing.pem" -pubout -out "$OAUTH_GRANT_RUNTIME/public.pem"
printf 'Cratis__AuthProxy__Services__grants__ForwardedIdentity__PrivateKeyPkcs8Base64=%s\n' "$(openssl base64 -A -in "$OAUTH_GRANT_RUNTIME/signing.der")" > "$OAUTH_GRANT_RUNTIME/signing.conf"

echo "== Receiver conformance (pinned Arc v2 vectors)"
dotnet run --project E2E/OAuthGrantReceiver/OAuthGrantReceiver.csproj -c Release -- --self-test

echo "== Publishing AuthProxy"
# Keep disposable build output outside Source, and keep private runtime material outside the image context.
image_context="$logs/image-context"
mkdir -p "$image_context"
dotnet publish Source/AuthProxy/AuthProxy.csproj -c Release -o "$image_context/Source/AuthProxy/out" \
  -p:CreateHardLinksForPublishFilesIfPossible=false -p:CreateSymbolicLinksForPublishFilesIfPossible=false

echo "== Building the AuthProxy image"
docker build -f "$root/Docker/Development/Dockerfile" -t "$AUTHPROXY_IMAGE" "$image_context"

echo "== Starting AuthProxy, the Arc sample, the TLS issuer and the independent receiver"
"${compose[@]}" up -d --build --wait --wait-timeout 180

echo "== Running the client"
dotnet run --project E2E/Client/Client.csproj -c Release

echo "== Running the OAuth-grant lane"
"${compose[@]}" --profile test build grant-client
"${compose[@]}" --profile test run --rm --no-deps grant-client
