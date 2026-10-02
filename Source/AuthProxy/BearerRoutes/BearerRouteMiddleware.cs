// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.Tenancy;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// The gate for bearer routes: authenticates a request on a bearer route by its access token alone and forwards
/// it, and refuses a bearer-route token anywhere else.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="validator">The access-token validator.</param>
/// <param name="accessPolicy">The deployment's claim requirements, applied to the token's principal.</param>
/// <param name="tenantVerifier">The tenant existence verifier, applied when tenant verification is configured.</param>
/// <param name="forwarder">The forwarder to the service backend.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// Placed ahead of static files, authentication and everything after them, so a request on a bearer route never
/// reaches the cookie session, provider selection, tenant selection or the reverse-proxy route table: it is
/// answered here, by a forward or by an API-style refusal, and nothing else. The only other thing it does is
/// refuse a token from a bearer-route issuer on a path that is not one of the bearer routes, so such a token
/// cannot authenticate a browser-only surface through any other bearer support the deployment has configured.
/// <para>
/// The deployment's claim requirements (<see cref="C.AuthProxy.Authorization"/> and the route's service's own)
/// apply here as they do to a browser session, to the principal after the route's claim mappings, unless the route
/// sets <see cref="C.BearerRoute.IgnoreDeploymentRequiredClaims"/>; the route's own
/// <see cref="C.BearerRoute.RequiredClaims"/> apply on top. Identity
/// verification through <c language="text">/.cratis/me</c> does not run here in either mode — not even the
/// <c language="text">403</c> veto <see cref="C.IdentityVerificationMode.BestEffort"/> applies to a browser session. A
/// deployment that requires verification may declare a bearer route only when the route says it accepts callers
/// without it (<see cref="C.BearerRoute.AcceptWithoutIdentityVerification"/>), which startup validation enforces;
/// otherwise a route that does not say so is reported at startup (<see cref="BearerRouteStartupReport"/>).
/// </para>
/// <para>
/// With no bearer route configured it hands every request on untouched.
/// </para>
/// </remarks>
public class BearerRouteMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    IBearerTokenValidator validator,
    IAccessPolicy accessPolicy,
    ITenantVerifier tenantVerifier,
    IBearerRouteForwarder forwarder,
    ILogger<BearerRouteMiddleware> logger)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var current = config.CurrentValue;
        if (BearerRouteTable.All(current).Count == 0)
        {
            await next(context);
            return;
        }

        // Reject aliases before selecting a route: a backend may normalize a path that would otherwise
        // miss every bearer prefix and fall through to browser-session authentication.
        if (!BearerRouteTable.IsUnambiguous(context.Request.Path))
        {
            logger.BearerRoutePathAmbiguous();
            BearerChallenge.BadRequest(context);
            return;
        }

        if (BearerRouteTable.TryMatchResourceMetadata(context.Request.Path, current, out var metadataRoute))
        {
            await ServeResourceMetadata(context, metadataRoute);
            return;
        }

        if (BearerRouteTable.TryMatch(context.Request.Path, current, out var route))
        {
            await Authenticate(context, route, current);
            return;
        }

        if (BearerTokenValidator.TryFindPresentedIssuer(context.Request, _ => BearerRouteTable.IsBearerRouteIssuer(_, current), out var issuer))
        {
            logger.BearerTokenOutsideItsRoutes(issuer, RequestPathRedaction.Redact(context.Request.Path));
            BearerChallenge.Unauthorized(context, resourceMetadataUrl: null, "invalid_token");
            return;
        }

        await next(context);
    }

    async Task ServeResourceMetadata(HttpContext context, ResolvedBearerRoute route)
    {
        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
        {
            BearerChallenge.NoStore(context);
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            context.Response.Headers[HeaderNames.Allow] = "GET, HEAD";
            return;
        }

        await forwarder.Forward(context, route, identity: null);
    }

    async Task Authenticate(HttpContext context, ResolvedBearerRoute route, C.AuthProxy current)
    {
        var validation = await validator.Validate(context.Request, route, context.RequestAborted);
        if (!validation.Succeeded)
        {
            logger.BearerTokenRefused(route.Prefix, route.ServiceName, validation.Status, validation.Reason ?? string.Empty);
            BearerChallenge.Write(context, validation, route);
            return;
        }

        var decision = accessPolicy.Evaluate(validation.Principal!, current, route.ServiceName, route.Route);
        if (!decision.IsGranted)
        {
            logger.BearerAccessDenied(route.Prefix, route.ServiceName, decision.UnsatisfiedClaim);
            BearerChallenge.Forbidden(context);
            return;
        }

        if (!await tenantVerifier.VerifyAsync(validation.TenantId!))
        {
            logger.BearerTenantNotVerified(validation.TenantId!, RequestPathRedaction.Redact(context.Request.Path));
            BearerChallenge.Forbidden(context);
            return;
        }

        context.User = validation.Principal!;
        await forwarder.Forward(context, route, BearerForwardedIdentity.From(validation, route));
    }
}
