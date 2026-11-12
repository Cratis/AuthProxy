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
compose=(docker compose -f E2E/docker-compose.yml)

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "E2E failed (exit $status); container logs saved to $logs"
    "${compose[@]}" logs --no-color > "$logs/compose.log" 2>&1 || true
    tail -n 60 "$logs/compose.log" || true
  fi
  "${compose[@]}" down -v --remove-orphans > /dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

echo "== Publishing AuthProxy"
rm -rf Source/AuthProxy/out
dotnet publish Source/AuthProxy/AuthProxy.csproj -c Release -o Source/AuthProxy/out

echo "== Building the AuthProxy image"
docker build -f Docker/Development/Dockerfile -t "$AUTHPROXY_IMAGE" .

echo "== Starting AuthProxy and the Arc sample"
"${compose[@]}" up -d --build --wait --wait-timeout 180

echo "== Running the client"
dotnet run --project E2E/Client/Client.csproj -c Release
