// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Works out what each bearer route leaves unchecked that the deployment otherwise checks.
/// </summary>
/// <remarks>
/// Each of these is a deliberate configuration, or the default one, which is why none of them refuses to start.
/// Each also means a caller can reach the service through the route who would be refused through a browser
/// session, which is why none of them is allowed to be silent either.
/// <para>
/// A bearer route does not call <c language="text">/.cratis/me</c> — not even for the <c language="text">403</c> veto the default
/// <see cref="C.IdentityVerificationMode.BestEffort"/> applies to a browser session. The endpoint is written for
/// browser sessions, and a product cannot be assumed to answer it correctly for a principal authenticated by a
/// token: one that answered <c language="text">403</c> to every principal it did not recognize would lock out every token,
/// and one that answered <c language="text">200</c> would give the veto no meaning. The product's backend decides tenant
/// membership for a token instead, and the route says it accepts that through
/// <see cref="C.BearerRoute.AcceptWithoutIdentityVerification"/>, or is reported here.
/// </para>
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
        // Every participating service is asked for a browser session, whichever service the request targets, so
        // every one of them is a service whose refusal a bearer route does not get.
        var consulted = config.Services
            .Where(_ => _.Value.ParticipatesInIdentityResolution)
            .Select(_ => _.Key)
            .ToList();

        foreach (var route in BearerRouteTable.All(config))
        {
            if (consulted.Count > 0 && !route.Route.AcceptWithoutIdentityVerification)
            {
                yield return new BearerRouteWarning(BearerRouteWarningKind.IdentityVerificationNotConsulted, route.ServiceName, route.Prefix, consulted);
            }

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
