// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Logs, at startup, every <see cref="BearerRouteWarning"/> the configuration gives rise to.
/// </summary>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="logger">The logger.</param>
public sealed class BearerRouteStartupReport(IOptionsMonitor<C.AuthProxy> config, ILogger<BearerRouteStartupReport> logger) : IHostedService
{
    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var warning in BearerRouteWarnings.For(config.CurrentValue))
        {
            var subjects = string.Join(", ", warning.Subjects);
            switch (warning.Kind)
            {
                case BearerRouteWarningKind.DeploymentRequirementsIgnored:
                    logger.BearerRouteIgnoresDeploymentRequirements(warning.Prefix, warning.ServiceName, subjects);
                    break;
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
