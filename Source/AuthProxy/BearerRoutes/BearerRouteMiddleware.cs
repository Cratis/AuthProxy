// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.BearerRoutes.Introspection;
using Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;
using Cratis.AuthProxy.Tenancy;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// The gate for bearer routes: authenticates a request on a bearer route by its access token alone and forwards
/// it, and refuses a bearer-route token anywhere else.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="validator">The access-token validator.</param>
/// <param name="introspector">Asks a token's issuer whether the validated token is still active, when the issuer has introspection configured.</param>
/// <param name="accessPolicy">The deployment's claim requirements, applied to the token's principal.</param>
/// <param name="tenantVerifier">The tenant existence verifier, applied when tenant verification is configured.</param>
/// <param name="tenantResolver">The request's addressed tenants.</param>
/// <param name="forwarder">The forwarder to the service backend.</param>
/// <param name="tokenProtector">Recognizes access tokens AuthProxy issued through its client-credentials grant.</param>
/// <param name="logger">The logger.</param>
/// <param name="dpop">The opt-in per-request proof enforcement service.</param>
/// <remarks>
/// Placed after endpoint selection but ahead of static files, authentication and everything after them, so a
/// request on a bearer route never reaches the cookie session, provider selection, tenant selection or reverse-proxy
/// forwarding: it is answered here, by a forward or by an API-style refusal. Selected passthrough routes are exempt
/// before any token is read. The only other thing it does is
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
/// A bearer route whose prefix is exactly its service's client-credentials route prefix also carries the tokens
/// AuthProxy issues through its client-credentials grant. A credential this gate verifies as such a token is judged
/// by the client-credentials rules only: it is handed on to the client-credentials authentication when it was issued
/// for this service and prefix and refused here otherwise. Every other credential is judged by the bearer route only.
/// </para>
/// <para>
/// With no bearer route configured it hands every request on untouched.
/// </para>
/// </remarks>
public class BearerRouteMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    IBearerTokenValidator validator,
    IBearerTokenIntrospector introspector,
    IAccessPolicy accessPolicy,
    ITenantVerifier tenantVerifier,
    ITenantResolver tenantResolver,
    IBearerRouteForwarder forwarder,
    ClientCredentialsTokenProtector tokenProtector,
    ILogger<BearerRouteMiddleware> logger,
    Dpop.DpopEnforcement? dpop = null)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var current = config.CurrentValue;
        if (AnonymousPaths.PassesCallerAuthorization(context) || BearerRouteTable.All(current).Count == 0)
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

    static bool AllowsTransport(HttpContext context, C.AuthProxy current) =>
        context.Request.IsHttps
        || current.Profile == C.DeploymentProfile.LocalDevelopment
        || IsLoopbackRequest(context);

    /// <summary>
    /// Requires both the effective peer and the host to be loopback: a remote caller's forged Host header
    /// alone, or a loopback ingress serving a public hostname, does not earn the exemption. A loopback peer
    /// that relays a client's Host header is part of the deployment's trust boundary, so deployments must not
    /// run an untrusted local relay in front of the proxy.
    /// </summary>
    /// <param name="context">The request context after trusted forwarded-header processing.</param>
    /// <returns>Whether both the effective remote address and host are loopback.</returns>
    static bool IsLoopbackRequest(HttpContext context) =>
        context.Connection.RemoteIpAddress is { } peer
        && IPAddress.IsLoopback(peer)
        && Uri.TryCreate($"http://{context.Request.Host}/", UriKind.Absolute, out var uri)
        && uri.IsLoopback;

    async Task ServeResourceMetadata(HttpContext context, ResolvedBearerRoute route)
    {
        // A route that accepts personal access tokens only has no OAuth metadata to serve, and nothing is
        // forwarded for it: the answer is the same for every method.
        if (route.Profile == BearerProfile.PatOnly)
        {
            BearerChallenge.MetadataNotFound(context);
            return;
        }

        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
        {
            BearerChallenge.MethodNotAllowed(context);
            return;
        }

        await forwarder.Forward(context, route, identity: null);
    }

    async Task Authenticate(HttpContext context, ResolvedBearerRoute route, C.AuthProxy current)
    {
        if (!AllowsTransport(context, current))
        {
            BearerChallenge.HttpsRequired(context);
            return;
        }

        if (RequestAuthentication.HasBearer(context.Request) && RequestAuthentication.HasSession(context))
        {
            BearerChallenge.MultipleCredentials(context);
            return;
        }

        if (Dpop.DpopPresentation.RefuseUnsupported(context, route)) return;
        if (route.Route.Dpop is not null || !await TryHandleCredential(context, route, current))
        {
            await AuthenticateExternal(context, route, current);
        }
    }

    async Task<bool> TryHandleCredential(HttpContext context, ResolvedBearerRoute route, C.AuthProxy current)
    {
        // The credential's kind is decided once, here. The branch it lands in is the only one that sees it: a
        // refusal is never retried as the other kind.
        var clientCredentialsPrefix = ClientCredentialsOnBearerRoutes.SharedPrefix(current, route);
        IssuedBearerRouteCredential? issued = null;
        var recognizer = clientCredentialsPrefix is null ? null : (Func<string, bool>)(token => TryRecognizeIssued(token, route, out issued));
        var (dispatch, reason) = CredentialDispatcher.Dispatch(context.Request, route, recognizer);
        switch (dispatch)
        {
            case CredentialDispatch.ClientCredentials:
                await HandOnIssuedToken(context, route, clientCredentialsPrefix!, issued);
                return true;

            case CredentialDispatch.Ambiguous:
                logger.BearerTokenRefused(route.Prefix, route.ServiceName, BearerTokenValidationStatus.Invalid, reason);
                BearerChallenge.MultipleCredentials(context);
                return true;

            case CredentialDispatch.Refused:
                logger.BearerTokenRefused(route.Prefix, route.ServiceName, BearerTokenValidationStatus.Invalid, reason);
                BearerChallenge.Write(context, BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, reason), route);
                return true;

            case CredentialDispatch.Missing:
                BearerChallenge.Write(context, BearerTokenValidation.Refused(BearerTokenValidationStatus.Missing, "No bearer token was presented."), route);
                return true;

            case CredentialDispatch.PersonalAccessToken:
                // The service behind the route verifies the token; this gate only recognized it and checked it names
                // this route's resource.
                context.Items[BearerRouteDefaults.PassThroughAuthorizationItemKey] = true;
                await forwarder.Forward(context, route, identity: null);
                return true;
        }

        return false;
    }

    async Task AuthenticateExternal(HttpContext context, ResolvedBearerRoute route, C.AuthProxy current)
    {
        var validation = await Dpop.DpopEnforcement.ValidateToken(dpop, validator, context, route);
        if (validation is null) return;
        if (!validation.Succeeded)
        {
            logger.BearerTokenRefused(route.Prefix, route.ServiceName, validation.Status, validation.Reason ?? string.Empty);
            Dpop.DpopChallenge.Write(context, validation, route);
            return;
        }

        if (!await IsConfirmedActive(context, route, validation)) return;

        validation = await Dpop.DpopEnforcement.Verify(dpop, context, route, validation);
        if (validation is null) return;
        if (!await MayForwardExternal(context, route, current, validation)) return;

        context.User = validation.Principal!;
        Dpop.DpopEnforcement.PrepareForward(context, validation);
        await forwarder.Forward(context, route, BearerForwardedIdentity.From(validation, route));
    }

    async Task<bool> MayForwardExternal(HttpContext context, ResolvedBearerRoute route, C.AuthProxy current, BearerTokenValidation validation)
    {
        if (BindingConflicts(context, current, route, validation))
        {
            BearerChallenge.Forbidden(context);
            return false;
        }

        var decision = accessPolicy.Evaluate(validation.Principal!, current, route.ServiceName, route.Route);
        if (!decision.IsGranted)
        {
            logger.BearerAccessDenied(route.Prefix, route.ServiceName, decision.UnsatisfiedClaim);
            BearerChallenge.Forbidden(context);
            return false;
        }

        if (await tenantVerifier.VerifyAsync(validation.TenantId!)) return true;
        logger.BearerTenantNotVerified(validation.TenantId!, RequestPathRedaction.Redact(context.Request.Path));
        BearerChallenge.Forbidden(context);
        return false;
    }

    bool TryRecognizeIssued(string token, ResolvedBearerRoute route, out IssuedBearerRouteCredential? credential)
    {
        credential = null;

        if (!ClientCredentialsOnBearerRoutes.CouldBeIssued(token))
        {
            return false;
        }

        if (!tokenProtector.TryValidate(token, out var validated, out var expiresAt))
        {
            return tokenProtector.IsIssued(token);
        }

        credential = new(route, token, validated, expiresAt);
        return true;
    }

    async Task HandOnIssuedToken(HttpContext context, ResolvedBearerRoute route, string prefix, IssuedBearerRouteCredential? credential)
    {
        if (credential is null)
        {
            BearerChallenge.Unauthorized(context, route.ResourceMetadataUrl, "invalid_token");
            return;
        }

        // The token is AuthProxy's own, so the client-credentials rules alone judge it and a refusal here is final.
        if (!ClientCredentialsOnBearerRoutes.IsIssuedFor(credential.Payload, route, prefix, context.Request.Path))
        {
            const string reason = "client-credentials token issued for another service or route prefix";
            logger.BearerTokenRefused(route.Prefix, route.ServiceName, BearerTokenValidationStatus.Invalid, reason);
            BearerChallenge.Write(context, BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, reason), route);
            return;
        }

        context.Items[ClientCredentialsDefaults.ValidatedTokenPayloadItemKey] = credential.Payload;
        IssuedBearerRouteCredential.Store(context, credential);
        await next(context);
    }

    async Task<bool> IsConfirmedActive(HttpContext context, ResolvedBearerRoute route, BearerTokenValidation validation)
    {
        if (validation.Issuer is not { Introspection: not null } issuer)
        {
            return true;
        }

        // The token was read once already, by the same strict reading; failing to read it again refuses, never trusts.
        var verdict = BearerTokenValidator.TryReadStrictBearerToken(context.Request, out var token)
            ? await introspector.Introspect(token, validation, issuer, context.RequestAborted)
            : IntrospectionVerdict.Inactive;

        switch (verdict)
        {
            case IntrospectionVerdict.Active:
                return true;

            case IntrospectionVerdict.Unavailable when route.Route.IntrospectionUnavailable == C.IntrospectionFailurePolicy.Accept
                && Dpop.DpopIntrospection.AllowsUnavailable(route):
                logger.IntrospectionUnavailableAccepted(issuer.Issuer, route.Prefix, route.ServiceName);
                return true;

            case IntrospectionVerdict.Unavailable:
                logger.BearerIntrospectionRefused(issuer.Issuer, route.Prefix, route.ServiceName);
                BearerChallenge.Write(context, BearerTokenValidation.Refused(BearerTokenValidationStatus.IntrospectionUnavailable, "The issuer's introspection endpoint is unavailable."), route);
                return false;

            default:
                logger.BearerTokenRevoked(route.Prefix, route.ServiceName);
                Dpop.DpopChallenge.Write(context, BearerTokenValidation.Refused(BearerTokenValidationStatus.Revoked, "The issuer reports the token is not active."), route);
                return false;
        }
    }

    bool BindingConflicts(HttpContext context, C.AuthProxy current, ResolvedBearerRoute route, BearerTokenValidation validation)
    {
        var environmentConflict = route.Route.EnvironmentClaimType.Length > 0
            && !CredentialTarget.Matches(validation.Environment, current.CredentialBinding.Environment);
        var tenantConflict = tenantResolver.ResolveEach(context)
            .Any(target => CredentialTarget.IsAddressedByRequest(target.Strategy, bearerRoute: true)
                && !CredentialTarget.MatchesTenant(validation.TenantId, target.TenantId));
        if (!environmentConflict && !tenantConflict) return false;
        logger.BearerCredentialBoundElsewhere(route.Prefix, route.ServiceName, environmentConflict ? "environment" : "tenant", RequestPathRedaction.Redact(context.Request.Path));
        return true;
    }
}
