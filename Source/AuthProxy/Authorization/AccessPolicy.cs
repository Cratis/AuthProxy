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
/// <c language="text">Authorization</c> section would silently be the way in.
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
    public AccessDecision Evaluate(HttpContext context, C.AuthProxy config) =>
        Evaluate(context.User, RequirementsFor(config, ResolveService(context, config)));

    /// <inheritdoc/>
    public AccessDecision Evaluate(ClaimsPrincipal user, C.AuthProxy config, string serviceName, C.BearerRoute route)
    {
        var requirements = route.IgnoreDeploymentRequiredClaims
            ? route.RequiredClaims
            : RequirementsFor(config, FindService(config, serviceName)).Concat(route.RequiredClaims);

        return Evaluate(user, requirements);
    }

    static AccessDecision Evaluate(ClaimsPrincipal user, IEnumerable<C.ClaimRequirement> requirements)
    {
        foreach (var requirement in requirements)
        {
            if (!IsSatisfied(requirement, user))
            {
                return AccessDecision.Denied(requirement.Claim);
            }
        }

        return AccessDecision.Granted;
    }

    /// <summary>
    /// Gets every requirement that applies to a request: the root's, then the target service's.
    /// </summary>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <param name="service">The targeted service, if any.</param>
    /// <returns>The applicable requirements, root-first.</returns>
    static IEnumerable<C.ClaimRequirement> RequirementsFor(C.AuthProxy config, C.Service? service)
    {
        foreach (var requirement in config.Authorization.RequiredClaims)
        {
            yield return requirement;
        }

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
    /// Endpoint selection runs before the gate, so route metadata is authoritative when present. For
    /// callers evaluating a request without a selected endpoint, a single-service deployment selects its
    /// only service; otherwise a configured header target wins, with the <c language="text">service</c> query
    /// parameter as the fallback. An unknown header must not hide a query-selected service's requirements.
    /// </remarks>
    static C.Service? ResolveService(HttpContext context, C.AuthProxy config)
    {
        if (ServiceSelection.FromRoute(context) is { } selectedService)
        {
            return FindService(config, selectedService);
        }

        if (config.Services.Count == 1)
        {
            return config.Services.Values.First();
        }

        return FindService(config, ServiceSelection.FromHeaders(context.Request.Headers))
            ?? FindService(config, context.Request.Query[ServiceQueryParameter].FirstOrDefault());
    }

    static C.Service? FindService(C.AuthProxy config, string? serviceId) =>
        string.IsNullOrWhiteSpace(serviceId)
            ? null
            : config.Services
                .Where(_ => string.Equals(_.Key, serviceId.Trim(), StringComparison.OrdinalIgnoreCase))
                .Select(_ => _.Value)
                .FirstOrDefault();

    /// <summary>
    /// Determines whether a principal satisfies a single requirement.
    /// </summary>
    /// <param name="requirement">The requirement to evaluate.</param>
    /// <param name="user">The authenticated principal.</param>
    /// <returns><see langword="true"/> when the requirement is satisfied; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// A requirement naming no claim can never be satisfied, so it denies. That is the fail-closed
    /// direction, and the opposite of how an unusable <c language="text">AnonymousPaths</c> entry is treated: discarding an
    /// entry there leaves a path authenticated, discarding a requirement here would let everybody in.
    /// Startup validation refuses the configuration outright, so this is the second line rather than the
    /// first.
    /// <para>
    /// Values are compared case-insensitively. The values being matched are organization names, team
    /// slugs, group names and roles — identifiers their own systems treat as case-insensitive — so an
    /// ordinal comparison would turn <c language="text">cratis</c> against <c language="text">Cratis</c> into a locked-out deployment with
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
