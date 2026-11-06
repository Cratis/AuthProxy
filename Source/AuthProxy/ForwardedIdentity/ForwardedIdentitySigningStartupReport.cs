// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Logs per-flow signing policy at startup without logging credentials or proofs.</summary>
/// <param name="config">The validated gateway configuration.</param>
/// <param name="logger">The startup diagnostic logger.</param>
internal sealed class ForwardedIdentitySigningStartupReport(IOptionsMonitor<C.AuthProxy> config, ILogger<ForwardedIdentitySigningStartupReport> logger) : IHostedService
{
    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var row in ForwardedIdentitySigningReport.For(config.CurrentValue))
        {
            if (row.IsAttested) logger.FlowAttested(row.Flow, row.ServiceName);
            else if (row.IsSigned) logger.FlowSigned(row.Flow, row.ServiceName, row.KeyId!, row.Audience!);
            else logger.FlowUnsigned(row.Flow, row.ServiceName);
            logger.FlowTransport(row.Flow, row.ServiceName, row.Transport);
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
