// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Represents what AuthProxy vouches for when it forwards a request authenticated on a bearer route.
/// </summary>
/// <param name="Principal">The principal sent in the Microsoft Identity Platform headers.</param>
/// <param name="TenantId">The tenant from the token, sent as <see cref="Headers.TenantId"/>.</param>
/// <param name="Scopes">The granted scopes, sent as <see cref="Headers.TokenScope"/>.</param>
/// <param name="ClientId">The client the token was issued to, sent as <see cref="Headers.TokenClientId"/>, when the token names one.</param>
/// <param name="ForwardAuthorizationHeader">Whether the <c language="text">Authorization</c> header travels to the backend too.</param>
public sealed record BearerForwardedIdentity(
    ClientPrincipal Principal,
    string TenantId,
    IReadOnlyList<string> Scopes,
    string? ClientId,
    bool ForwardAuthorizationHeader)
{
    /// <summary>
    /// Creates the forwarded identity for a successfully validated token.
    /// </summary>
    /// <param name="validation">The successful validation.</param>
    /// <param name="route">The route the token was validated for.</param>
    /// <returns>The forwarded identity.</returns>
    /// <remarks>
    /// The principal is built the way a browser session's is: the user id from <c language="text">sub</c> and the user
    /// details from <c language="text">preferred_username</c>, then <c language="text">name</c> — after the route's claim mappings
    /// have applied, so a route can present the identity the backend already knows (for example the GitHub id
    /// and login a GitHub browser session carries). The only roles are <c language="text">anonymous</c> and
    /// <c language="text">authenticated</c>: a token never grants a role.
    /// </remarks>
    public static BearerForwardedIdentity From(BearerTokenValidation validation, ResolvedBearerRoute route)
    {
        var user = validation.Principal!;
        var subject = user.Claims.FirstOrDefault(_ => string.Equals(_.Type, "sub", StringComparison.Ordinal))?.Value ?? string.Empty;
        var details = user.Claims.FirstOrDefault(_ => string.Equals(_.Type, "preferred_username", StringComparison.Ordinal))?.Value
            ?? user.Claims.FirstOrDefault(_ => string.Equals(_.Type, "name", StringComparison.Ordinal))?.Value
            ?? subject;

        var principal = new ClientPrincipal
        {
            IdentityProvider = route.IdentityProvider,
            UserId = subject,
            UserDetails = details,
            UserRoles = ["anonymous", "authenticated"],
            Claims = [.. user.Claims.Select(_ => new ClientPrincipalClaim { Type = _.Type, Value = _.Value })],
        };

        return new BearerForwardedIdentity(
            principal,
            validation.TenantId!,
            [.. user.FindAll(BearerRouteClaims.Scope).Select(_ => _.Value)],
            user.FindFirst(BearerRouteClaims.ClientId)?.Value,
            route.Route.ForwardAuthorizationHeader);
    }
}
