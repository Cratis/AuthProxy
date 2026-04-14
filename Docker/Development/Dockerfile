# syntax=docker/dockerfile:1

####################################
# Cratis AuthProxy
# Build runtime image.
####################################

# ── Stage 1: Build the frontend (Web) ─────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /src
# Copy Web source and Ingress destination so the relative output path works
COPY Source/Web/ ./Web/
COPY Source/AuthProxy/ ./Ingress/

WORKDIR /src/Web
RUN npm ci && npm run build

# ── Stage 2: Build the .NET backend ────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS backend-builder
ARG VERSION

WORKDIR /build

COPY Directory.Build.props Directory.Packages.props ./
COPY Source/AuthProxy/ ./Source/AuthProxy/
# Copy the compiled frontend assets into the wwwroot directory
COPY --from=frontend-builder /src/Ingress/wwwroot ./Source/AuthProxy/wwwroot

RUN dotnet publish Source/AuthProxy/AuthProxy.csproj \
    -c Release \
    -o /out \
    /p:Version=${VERSION:-0.0.0}

# ── Stage 3: Runtime image ─────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble
ARG VERSION

RUN echo Version = ${VERSION}

# Install Tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Add Tini to get a real init process
RUN ARCH=$(dpkg --print-architecture) && \
    curl -LJ https://github.com/krallin/tini/releases/download/v0.19.0/tini-${ARCH} --output /usr/bin/tini && \
    chmod +x /usr/bin/tini

WORKDIR /app

COPY --from=backend-builder /out ./

ENTRYPOINT ["/usr/bin/tini", "--", "dotnet", "/app/AuthProxy.dll"]
