// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Cratis.AuthProxy.ReverseProxy;
using Yarp.ReverseProxy.Model;
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
    /// <inheritdoc/>
    public bool IsConfigured(C.AuthProxy config) =>
        config.Authorization.HasRequirements
        || config.Services.Values.Any(_ => _.Authorization?.HasRequirements == true);

    /// <inheritdoc/>
    public AccessDecision Evaluate(HttpContext context, C.AuthProxy config)
    {
        var service = ServiceRoutes.Resolve(context.Request, config)?.Service;
        if (service is null && context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>() is not null)
        {
            // A selected proxy endpoint can still forward the request. Never apply only root requirements
            // or a named service's requirements when its authoritative cluster cannot be resolved.
            return AccessDecision.Denied(string.Empty);
        }

        service ??= NamedService(context, config);
        foreach (var requirement in RequirementsFor(service, config))
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
    /// <param name="service">The targeted service, if any.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The applicable requirements, root-first.</returns>
    static IEnumerable<C.ClaimRequirement> RequirementsFor(C.Service? service, C.AuthProxy config)
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
    /// Resolves a service named by a request without a selected proxy endpoint.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The targeted service, or <see langword="null"/> when the request matches no service route.</returns>
    /// <remarks>
    /// A request that matches no service route is not forwarded at all. When it still names a service in the
    /// <c language="text">x-cratis-microservice</c> header (or legacy <c language="text">Service-ID</c>) or the
    /// <c language="text">service</c> query parameter, that service's requirements apply anyway — the stricter
    /// answer costs nothing for a request that goes nowhere. An unknown header does not hide a query-selected
    /// service's requirements. A request that names none gets only the root requirements.
    /// </remarks>
    static C.Service? NamedService(HttpContext context, C.AuthProxy config)
    {
        return FindService(config, ServiceSelection.FromHeaders(context.Request.Headers))
            ?? FindService(config, context.Request.Query[ServiceRoutes.ServiceQueryParameter].FirstOrDefault());
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
