// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Introspection;
using Cratis.AuthProxy.Ingress;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Logs, at startup, every <see cref="BearerRouteWarning"/> the configuration gives rise to.
/// </summary>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="logger">The logger.</param>
/// <param name="policy">The ingress trust boundary.</param>
public sealed class BearerRouteStartupReport(IOptionsMonitor<C.AuthProxy> config, ILogger<BearerRouteStartupReport> logger, ITrustedProxyPolicy policy) : IHostedService
{
    /// <summary>
    /// Initializes a report without a trusted ingress boundary.
    /// </summary>
    /// <param name="config">The auth proxy configuration.</param>
    /// <param name="logger">The logger.</param>
    public BearerRouteStartupReport(IOptionsMonitor<C.AuthProxy> config, ILogger<BearerRouteStartupReport> logger)
        : this(config, logger, new TrustedProxyPolicy(Options.Create(new C.Ingress())))
    {
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var warning in BearerRouteWarnings.For(config.CurrentValue, policy))
        {
            var subjects = string.Join(", ", warning.Subjects);
            switch (warning.Kind)
            {
                case BearerRouteWarningKind.DeploymentRequirementsIgnored:
                    logger.BearerRouteIgnoresDeploymentRequirements(warning.Prefix, warning.ServiceName, subjects);
                    break;

                case BearerRouteWarningKind.IdentityVerificationNotConsulted:
                    logger.BearerRouteDoesNotConsultIdentityVerification(warning.Prefix, warning.ServiceName, subjects);
                    break;

                case BearerRouteWarningKind.NoTrustedIngress:
                    logger.BearerRouteWithoutTrustedIngress(warning.Prefix, warning.ServiceName);
                    break;

                case BearerRouteWarningKind.RevocationNotEnforced:
                    logger.BearerRouteWithoutIntrospection(warning.Prefix, warning.ServiceName, subjects);
                    break;
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
