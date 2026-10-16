// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Authentication;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Begins the sign-in handshake with a configured identity provider, for the provider's login endpoint.
/// </summary>
/// <remarks>
/// Every way into a sign-in that is not an invitation, a credential link or a registration ends up here — the redirect
/// from the cookie handler, the provider-selection page and a link a person follows. With a
/// <see cref="C.SignIn.CallbackHost"/> a request on any other host is sent to the callback host first, see
/// <see cref="SignInCallbackHost"/>.
/// </remarks>
public static class LoginChallenge
{
    /// <summary>
    /// Begins the handshake, or answers why it cannot begin.
    /// </summary>
    /// <param name="scheme">The provider scheme from the route.</param>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="proxyConfig">The auth proxy configuration.</param>
    /// <param name="authConfig">The authentication configuration naming the providers.</param>
    /// <param name="tenantResolver">The tenant resolver used to capture tenant metadata in authentication state.</param>
    /// <param name="writeBody">Whether the refusal for an unknown provider carries a body, which a <c language="text">HEAD</c> request never does.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static async Task Begin(
        string scheme,
        HttpContext context,
        C.AuthProxy proxyConfig,
        C.Authentication authConfig,
        ITenantResolver tenantResolver,
        bool writeBody)
    {
        var providerExists = authConfig.OidcProviders.Any(p => OidcProviderScheme.FromName(p.Name) == scheme)
            || authConfig.OAuthProviders.Any(p => OidcProviderScheme.FromName(p.Name) == scheme);

        if (!providerExists)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            if (writeBody)
            {
                await context.Response.WriteAsync($"Provider '{scheme}' is not configured.");
            }

            return;
        }

        var returnUrl = context.Request.Query["returnUrl"].FirstOrDefault() ?? "/";
        if (SignInCallbackHost.TryBuildLoginBounce(context, proxyConfig, scheme, returnUrl, out var bounce))
        {
            context.Response.Redirect(bounce);
            return;
        }

        var properties = TenantAuthenticationState.CreateChallengeProperties(context, tenantResolver, returnUrl, proxyConfig);
        if (!InvitationAuthenticationState.TryBindPendingInvitation(context, properties))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        await context.ChallengeAsync(scheme, properties);
    }
}
