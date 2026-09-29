// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Works out what each bearer route leaves unchecked that the deployment otherwise checks.
/// </summary>
/// <remarks>
/// Each of these is a deliberate configuration, which is why none of them refuses to start. Each also means a
/// caller can reach the service through the route who would be refused through a browser session, which is why
/// none of them is allowed to be silent either.
/// </remarks>
public static class BearerRouteWarnings
{
    /// <summary>
    /// Gets the warnings for every resolvable bearer route in the configuration.
    /// </summary>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The warnings, one per route and kind.</returns>
    public static IEnumerable<BearerRouteWarning> For(C.AuthProxy config)
    {
        foreach (var route in BearerRouteTable.All(config))
        {
            if (route.Route.IgnoreDeploymentRequiredClaims)
            {
                var ignored = DeploymentRequirementClaims(config, route.ServiceName);
                if (ignored.Count > 0)
                {
                    yield return new BearerRouteWarning(BearerRouteWarningKind.DeploymentRequirementsIgnored, route.ServiceName, route.Prefix, ignored);
                }
            }
        }
    }

    static List<string> DeploymentRequirementClaims(C.AuthProxy config, string serviceName)
    {
        var service = config.Services
            .Where(_ => string.Equals(_.Key, serviceName, StringComparison.OrdinalIgnoreCase))
            .Select(_ => _.Value)
            .FirstOrDefault();

        return config.Authorization.RequiredClaims
            .Concat(service?.Authorization?.RequiredClaims ?? [])
            .Select(_ => _.Claim?.Trim() ?? string.Empty)
            .Where(_ => _.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }
}
