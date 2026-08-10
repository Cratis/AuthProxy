// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Extension methods for building a <see cref="ClientPrincipal"/> from an
/// <see cref="HttpContext"/> and for setting the Microsoft Identity headers.
/// </summary>
public static class ClientPrincipalExtensions
{
    /// <summary>
    /// Builds a <see cref="ClientPrincipal"/> from the authenticated
    /// <see cref="ClaimsPrincipal"/> on the given <paramref name="context"/>.
    /// Returns <see langword="null"/> when the user is not authenticated.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to read the claims from.</param>
    /// <returns>
    /// A populated <see cref="ClientPrincipal"/> when the user is authenticated;
    /// <see langword="null"/> otherwise.
    /// </returns>
    public static ClientPrincipal? BuildClientPrincipal(this HttpContext context)
    {
        var user = context.User;
        if (user.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        // Resolve against the scheme that actually authenticated this request — the framework records it in
        // the authenticate-result feature. The identity's AuthenticationType is NOT that scheme: an OIDC
        // token-validated identity carries "AuthenticationTypes.Federation", which no provider is registered
        // under, so resolving with it made every canonical OIDC session fail closed here — and the request
        // was then proxied without identity headers while the cookie session itself stayed perfectly valid.
        var authenticationScheme = context.Features.Get<IAuthenticateResultFeature>()?
                .AuthenticateResult?.Ticket?.AuthenticationScheme
            ?? user.Identity.AuthenticationType;

        var canonicalResolution = context.RequestServices is { } requestServices
            ? requestServices.GetService<ICanonicalIdentityResolver>()?.Resolve(user, authenticationScheme)
            : null;
        if (canonicalResolution?.IsConfigured == true)
        {
            if (!canonicalResolution.Succeeded || canonicalResolution.Identity is null || canonicalResolution.Principal is null)
            {
                return null;
            }

            user = canonicalResolution.Principal;
        }

        var identity = user.Identity!;

        var userId = canonicalResolution?.Identity?.Subject
            ?? user.FindFirst("oid")?.Value
            ?? user.FindFirst("sub")?.Value
            ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? string.Empty;

        var userDetails = user.FindFirst("preferred_username")?.Value
            ?? user.FindFirst("email")?.Value
            ?? user.FindFirst(ClaimTypes.Email)?.Value
            ?? user.FindFirst("name")?.Value
            ?? user.FindFirst(ClaimTypes.Name)?.Value
            ?? user.Identity?.Name
            ?? string.Empty;

        var isCanonical = canonicalResolution?.IsConfigured == true && canonicalResolution.Succeeded;
        var roles = user.Claims
            .Where(claim => IsRoleClaim(claim.Type, isCanonical))
            .Select(c => c.Value)
            .Concat(["anonymous", "authenticated"])
            .Distinct();

        var claims = user.Claims
            .Where(c => !IsRoleClaim(c.Type, isCanonical))
            .Select(c => new ClientPrincipalClaim { Type = c.Type, Value = c.Value });

        return new ClientPrincipal
        {
            IdentityProvider = canonicalResolution?.Identity?.ProviderKey ?? identity.AuthenticationType ?? "unknown",
            UserId = userId,
            UserDetails = userDetails,
            UserRoles = roles,
            Claims = claims,
        };
    }

    /// <summary>
    /// Adds the three Microsoft Identity Platform headers to an
    /// <see cref="HttpRequest"/> from the given <paramref name="principal"/>.
    /// </summary>
    /// <param name="request">The <see cref="HttpRequest"/> to enrich with identity headers.</param>
    /// <param name="principal">The <see cref="ClientPrincipal"/> whose identity to forward.</param>
    public static void SetMicrosoftIdentityHeaders(this HttpRequest request, ClientPrincipal principal)
    {
        request.Headers[Headers.Principal] = principal.ToBase64();
        request.Headers[Headers.PrincipalId] = principal.UserId;
        request.Headers[Headers.PrincipalName] = principal.UserDetails;
    }

    /// <summary>
    /// Adds the three Microsoft Identity Platform headers to an
    /// <see cref="HttpRequestMessage"/> from the given <paramref name="principal"/>.
    /// </summary>
    /// <param name="requestMessage">The outgoing HTTP request message to enrich.</param>
    /// <param name="principal">The <see cref="ClientPrincipal"/> whose identity to forward.</param>
    public static void SetMicrosoftIdentityHeaders(this HttpRequestMessage requestMessage, ClientPrincipal principal)
    {
        requestMessage.Headers.Remove(Headers.Principal);
        requestMessage.Headers.Remove(Headers.PrincipalId);
        requestMessage.Headers.Remove(Headers.PrincipalName);
        requestMessage.Headers.Add(Headers.Principal, principal.ToBase64());
        requestMessage.Headers.Add(Headers.PrincipalId, principal.UserId);
        requestMessage.Headers.Add(Headers.PrincipalName, principal.UserDetails);
    }

    static bool IsRoleClaim(string claimType, bool isCanonical) =>
        string.Equals(claimType, ClaimTypes.Role, StringComparison.Ordinal)
        || (isCanonical
            && (string.Equals(claimType, "role", StringComparison.Ordinal)
                || string.Equals(claimType, "roles", StringComparison.Ordinal)));
}
