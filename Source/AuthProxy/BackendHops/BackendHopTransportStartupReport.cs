// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Reports effective backend transport without credential content.
/// </summary>
/// <param name="config">The effective deployment configuration.</param>
/// <param name="source">The validated material.</param>
/// <param name="logger">The startup logger.</param>
internal sealed class BackendHopTransportStartupReport(IOptionsMonitor<C.AuthProxy> config, IBackendTlsMaterialSource source, ILogger<BackendHopTransportStartupReport> logger) : IHostedService
{
    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var current = config.CurrentValue;
        var material = source.Current;
        logger.Material(material.TrustAnchors.Count, material.ClientCertificate?.Subject, material.ClientCertificate?.Extensions["2.5.29.17"]?.Format(false), material.ClientCertificate?.GetCertHashString(HashAlgorithmName.SHA256), material.ClientCertificate?.NotAfter);
        foreach (var hop in BackendHopHosts.SignedHops(current))
        {
            var tls = Uri.TryCreate(hop.Address, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
            if (current.Profile == C.DeploymentProfile.LocalDevelopment && (!tls || material.ClientCertificate is null)) logger.LocalException(hop.Name);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
