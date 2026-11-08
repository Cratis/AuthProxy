// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Decides how a client-credentials route prefix and a bearer route relate when they claim the same paths.
/// </summary>
/// <remarks>
/// The one supported overlap is a bearer route whose prefix is exactly its own service's client-credentials route
/// prefix. Every other overlap — one prefix nested in the other, or a prefix of another service — is refused at
/// startup, because the bearer route would claim paths that client credentials address and a token's route could
/// no longer be told from its path alone.
/// </remarks>
public static class ClientCredentialsOnBearerRoutes
{
    /// <summary>
    /// Gets the client-credentials route prefix a bearer route shares, when its service declares client credentials
    /// on exactly the route's prefix.
    /// </summary>
    /// <param name="config">The AuthProxy configuration.</param>
    /// <param name="route">The bearer route.</param>
    /// <returns>The shared prefix, or <see langword="null"/> when the route shares none.</returns>
    public static string? SharedPrefix(C.AuthProxy config, ResolvedBearerRoute route)
    {
        if (!config.Services.TryGetValue(route.ServiceName, out var service) || service.ClientCredentials is null)
        {
            return null;
        }

        var prefix = ClientCredentialsServiceResolver.NormalizeRoutePrefix(service.ClientCredentials.RoutePrefix);
        return string.Equals(prefix, route.Prefix, StringComparison.OrdinalIgnoreCase) ? prefix : null;
    }

    /// <summary>
    /// Tells whether a bearer credential has the shape of a token AuthProxy issues, before any key is tried.
    /// </summary>
    /// <param name="token">The bearer credential.</param>
    /// <returns><see langword="true"/> when the credential could be an issued token.</returns>
    /// <remarks>An issued token is base64url and never has a dot; a JWT always has two, so it is not even tried.</remarks>
    public static bool CouldBeIssued(string token) => token.Length > 0 && !token.Contains('.', StringComparison.Ordinal);

    /// <summary>
    /// Tells whether a verified client-credentials token was issued for a bearer route's service and its shared prefix.
    /// </summary>
    /// <param name="payload">The verified token payload.</param>
    /// <param name="route">The bearer route the token was presented on.</param>
    /// <param name="prefix">The client-credentials prefix the route shares.</param>
    /// <param name="path">The request path.</param>
    /// <returns><see langword="true"/> when the token may be used on the request.</returns>
    public static bool IsIssuedFor(ClientCredentialsTokenPayload payload, ResolvedBearerRoute route, string prefix, PathString path)
    {
        var sameService = string.Equals(payload.Service, route.ServiceName, StringComparison.OrdinalIgnoreCase);
        var samePrefix = string.Equals(payload.RoutePrefix, prefix, StringComparison.OrdinalIgnoreCase);
        return sameService && samePrefix && path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Describes why a bearer route may not coexist with a client-credentials route prefix, if it may not.
    /// </summary>
    /// <param name="routeService">The service the bearer route belongs to.</param>
    /// <param name="routePrefix">The bearer route's normalized prefix.</param>
    /// <param name="clientCredentialsService">The service declaring client credentials.</param>
    /// <param name="clientCredentials">The client-credentials configuration.</param>
    /// <returns>The reason the two conflict, or <see langword="null"/> when they do not.</returns>
    public static string? Conflict(string routeService, string routePrefix, string clientCredentialsService, C.ServiceClientCredentials clientCredentials)
    {
        var prefix = ClientCredentialsServiceResolver.NormalizeRoutePrefix(clientCredentials.RoutePrefix);

        // The root prefix covers every path, which segment matching alone does not report.
        var overlaps = prefix == "/"
            || new PathString(routePrefix).StartsWithSegments(prefix)
            || new PathString(prefix).StartsWithSegments(routePrefix);
        if (!overlaps)
        {
            return null;
        }

        var sameService = string.Equals(routeService, clientCredentialsService, StringComparison.OrdinalIgnoreCase);
        if (sameService && string.Equals(routePrefix, prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var why = sameService
            ? "one is nested in the other"
            : "they belong to different services";
        return $"overlaps the client-credentials {nameof(C.ServiceClientCredentials.RoutePrefix)} '{prefix}' of service '{clientCredentialsService}', and {why}. " +
            "A bearer route may share a path with client credentials only when it is exactly its own service's client-credentials route prefix; " +
            "use that prefix, or prefixes that do not overlap.";
    }
}
