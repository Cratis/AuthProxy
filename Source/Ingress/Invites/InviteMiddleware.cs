// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using System.Net.Http.Json;
using Cratis.Ingress.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace Cratis.Ingress.Invites;

/// <summary>
/// Middleware that implements the two-phase invite flow:
/// <list type="number">
///   <item>
///     Handles <c>/invite/{token}</c> – validates the token, stores it in a short-lived
///     HTTP-only cookie and redirects the user to the OIDC login.
///   </item>
///   <item>
///     After a successful OIDC login – detects the pending invite cookie, calls the Studio
///     exchange endpoint and then deletes the cookie before continuing the request pipeline.
///   </item>
/// </list>
/// </summary>
public class InviteMiddleware(
    RequestDelegate next,
    IInviteTokenValidator tokenValidator,
    IOptionsMonitor<IngressConfig> config,
    IHttpClientFactory httpClientFactory,
    ILogger<InviteMiddleware> logger)
{
    /// <summary>The route prefix that triggers invite handling.</summary>
    public const string InvitePathPrefix = WellKnownPaths.InvitePathPrefix;

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        // ── Phase 1: incoming invite URL ──────────────────────────────────────
        if (context.Request.Path.StartsWithSegments(InvitePathPrefix, out var remaining))
        {
            var token = remaining.Value?.TrimStart('/');
            if (string.IsNullOrEmpty(token))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            if (!tokenValidator.Validate(token))
            {
                logger.InviteTokenValidationFailed(context.Request.Path);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            // Store the invite token in a short-lived, HTTP-only cookie.
            context.Response.Cookies.Append(Cookies.InviteToken, token, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = context.Request.IsHttps,
                MaxAge = TimeSpan.FromMinutes(15),
            });

            // Trigger OIDC login – the challenge will redirect the user to the IdP.
            await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme);
            return;
        }

        // ── Phase 2: post-login invite exchange ───────────────────────────────
        if (context.User.Identity?.IsAuthenticated == true
            && context.Request.Cookies.TryGetValue(Cookies.InviteToken, out var inviteToken))
        {
            var exchangeSucceeded = await ExchangeInvite(context, inviteToken);

            // Always delete the invite cookie regardless of exchange outcome so
            // the user is never stuck in a retry loop.
            context.Response.Cookies.Delete(Cookies.InviteToken);

            // After a successful exchange redirect the user to the lobby so they
            // can enter the application with their newly assigned tenant – unless
            // the invite is a tenant-issued invite that matches the resolved tenant,
            // in which case the user passes directly through to the microservice.
            if (exchangeSucceeded)
            {
                if (IsTenantIssuedInvite(inviteToken, context))
                {
                    await next(context);
                    return;
                }

                var lobbyUrl = config.CurrentValue.Invite?.Lobby?.Frontend?.BaseUrl;
                if (!string.IsNullOrWhiteSpace(lobbyUrl))
                {
                    context.Response.Redirect(lobbyUrl);
                    return;
                }
            }
        }

        await next(context);
    }

    async Task<bool> ExchangeInvite(HttpContext context, string inviteToken)
    {
        var exchangeUrl = config.CurrentValue.Invite?.ExchangeUrl;
        if (string.IsNullOrWhiteSpace(exchangeUrl))
        {
            logger.InviteExchangeUrlNotConfigured();
            return false;
        }

        var subject = context.User.FindFirst("sub")?.Value
            ?? context.User.FindFirst("oid")?.Value
            ?? string.Empty;

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, exchangeUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", inviteToken);
        request.Content = JsonContent.Create(new { subject });

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request);
        }
        catch (Exception ex)
        {
            logger.FailedToCallInviteExchangeEndpoint(ex, exchangeUrl);
            return false;
        }

        if (!response.IsSuccessStatusCode)
        {
            logger.InviteExchangeEndpointFailed((int)response.StatusCode, subject);
            return false;
        }

        logger.InviteExchangedSuccessfully(subject);
        return true;
    }

    bool IsTenantIssuedInvite(string inviteToken, HttpContext context)
    {
        var tenantClaim = config.CurrentValue.Invite?.TenantClaim;
        if (string.IsNullOrEmpty(tenantClaim))
        {
            return false;
        }

        if (!tokenValidator.TryGetClaim(inviteToken, tenantClaim, out var tokenTenantIdStr))
        {
            return false;
        }

        if (!Guid.TryParse(tokenTenantIdStr, out var tokenTenantId))
        {
            return false;
        }

        if (!context.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var resolvedTenantObj)
            || resolvedTenantObj is not Guid resolvedTenantId)
        {
            return false;
        }

        return tokenTenantId != Guid.Empty && tokenTenantId == resolvedTenantId;
    }
}
