# syntax=docker/dockerfile:1

####################################
# Cratis AuthProxy
# Runtime image — binaries pre-built on the GitHub runner.
####################################

FROM mcr.microsoft.com/dotnet/aspnet:11.0-resolute
ARG VERSION

RUN echo Version = ${VERSION}

# The package mirrors are reached over IPv4 with retries: name lookups for them failed intermittently on the build runners.
RUN printf 'Acquire::ForceIPv4 "true";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99network \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN ARCH=$(dpkg --print-architecture) && \
    curl -LJ https://github.com/krallin/tini/releases/download/v0.19.0/tini-${ARCH} --output /usr/bin/tini && \
    chmod +x /usr/bin/tini

WORKDIR /app

COPY Source/AuthProxy/out/ ./

ENTRYPOINT ["/usr/bin/tini", "--", "dotnet", "/app/AuthProxy.dll"]
