// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>
/// Decides whether an authenticated caller satisfies the claim requirements declared for the proxy and for
/// the service the request targets.
/// </summary>
/// <remarks>
/// The composition is deliberately the strict one in both directions: root requirements and service
/// requirements are <em>added</em> together rather than the service overriding the root, and every
/// requirement in the combined set has to hold. A service can therefore only ever narrow who reaches it,
/// which is the property that makes a root requirement worth writing — if a service section could replace
/// it, the root would be a default rather than a floor, and a service added later without an
/// <c>Authorization</c> section would silently be the way in.
/// </remarks>
public class AccessPolicy : IAccessPolicy
{
    /// <summary>
    /// The query-string parameter naming the target service, mirrored from the reverse-proxy route table.
    /// </summary>
    const string ServiceQueryParameter = "service";

    /// <inheritdoc/>
    public bool IsConfigured(C.AuthProxy config) =>
        config.Authorization.HasRequirements
        || config.Services.Values.Any(_ => _.Authorization?.HasRequirements == true);

    /// <inheritdoc/>
    public AccessDecision Evaluate(HttpContext context, C.AuthProxy config)
    {
        foreach (var requirement in RequirementsFor(context, config))
        {
            if (!IsSatisfied(requirement, context.User))
            {
                return AccessDecision.Denied(requirement.Claim);
            }
        }

        return AccessDecision.Granted;
    }

    /// <summary>
    /// Gets every requirement that applies to a request: the root's, then the target service's.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The applicable requirements, root-first.</returns>
    static IEnumerable<C.ClaimRequirement> RequirementsFor(HttpContext context, C.AuthProxy config)
    {
        foreach (var requirement in config.Authorization.RequiredClaims)
        {
            yield return requirement;
        }

        var service = ResolveService(context, config);
        if (service?.Authorization is null)
        {
            yield break;
        }

        foreach (var requirement in service.Authorization.RequiredClaims)
        {
            yield return requirement;
        }
    }

    /// <summary>
    /// Resolves the service a request targets, the same way the route table does.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The targeted service, or <see langword="null"/> when the request names none.</returns>
    /// <remarks>
    /// This runs before endpoint selection — the gate has to refuse a caller before anything reads a
    /// backend, and long before YARP picks a route — so the target is worked out from the request rather
    /// than from a selected endpoint. It mirrors <c>MicroserviceReverseProxyConfigProvider</c> exactly: a
    /// single-service deployment routes everything to that service, and beyond that a service is named by
    /// the <c>Service-ID</c> header or the <c>service</c> query parameter, header first.
    /// <para>
    /// A request in a multi-service deployment that names no service reaches no service route either, so
    /// answering <see langword="null"/> costs nothing: the root requirements still apply, and the request
    /// goes on to match nothing.
    /// </para>
    /// </remarks>
    static C.Service? ResolveService(HttpContext context, C.AuthProxy config)
    {
        if (config.Services.Count == 1)
        {
            return config.Services.Values.First();
        }

        var serviceId = context.Request.Headers[Headers.ServiceId].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(serviceId))
        {
            serviceId = context.Request.Query[ServiceQueryParameter].FirstOrDefault();
        }

        if (string.IsNullOrWhiteSpace(serviceId))
        {
            return null;
        }

        return config.Services
            .Where(_ => string.Equals(_.Key, serviceId.Trim(), StringComparison.OrdinalIgnoreCase))
            .Select(_ => _.Value)
            .FirstOrDefault();
    }

    /// <summary>
    /// Determines whether a principal satisfies a single requirement.
    /// </summary>
    /// <param name="requirement">The requirement to evaluate.</param>
    /// <param name="user">The authenticated principal.</param>
    /// <returns><see langword="true"/> when the requirement is satisfied; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// A requirement naming no claim can never be satisfied, so it denies. That is the fail-closed
    /// direction, and the opposite of how an unusable <c>AnonymousPaths</c> entry is treated: discarding an
    /// entry there leaves a path authenticated, discarding a requirement here would let everybody in.
    /// Startup validation refuses the configuration outright, so this is the second line rather than the
    /// first.
    /// <para>
    /// Values are compared case-insensitively. The values being matched are organization names, team
    /// slugs, group names and roles — identifiers their own systems treat as case-insensitive — so an
    /// ordinal comparison would turn <c>cratis</c> against <c>Cratis</c> into a locked-out deployment with
    /// nothing in the response to say why.
    /// </para>
    /// </remarks>
    static bool IsSatisfied(C.ClaimRequirement requirement, ClaimsPrincipal user)
    {
        if (string.IsNullOrWhiteSpace(requirement.Claim))
        {
            return false;
        }

        var claims = user.FindAll(requirement.Claim.Trim());
        var allowed = requirement.AnyOf;

        if (allowed.Count == 0)
        {
            return claims.Any();
        }

        return claims.Any(claim => allowed.Any(value => string.Equals(value.Trim(), claim.Value.Trim(), StringComparison.OrdinalIgnoreCase)));
    }
}
