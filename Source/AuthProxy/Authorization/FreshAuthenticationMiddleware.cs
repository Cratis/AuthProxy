// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>Requires a recent interactive authentication on opt-in protected service paths.</summary>
/// <param name="next">The remaining pipeline.</param>
/// <param name="options">The current configuration.</param>
/// <param name="clock">The authentication-age clock.</param>
/// <param name="logger">The privacy-safe event logger.</param>
public partial class FreshAuthenticationMiddleware(RequestDelegate next, IOptionsMonitor<C.AuthProxy> options, TimeProvider clock, ILogger<FreshAuthenticationMiddleware> logger)
{
    /// <summary>Checks freshness after authorization and authoritative service selection.</summary>
    /// <param name="context">The request context.</param>
    /// <returns>The asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        var config = options.CurrentValue;
        if (!FreshAuthenticationPolicy.AnyConfigured(config) || context.User.Identity?.IsAuthenticated != true
            || context.IsAnonymousPath(config) || context.IsLoginChallenge() || context.Request.Path.StartsWithSegments(WellKnownPaths.Cratis))
        {
            await next(context);
            return;
        }

        var service = ServiceRoutes.Resolve(context.Request, config);
        var route = context.GetEndpoint()?.Metadata.GetMetadata<Yarp.ReverseProxy.Model.RouteModel>();
        var prefix = route is not null
            ? route.Config.Metadata?.GetValueOrDefault(ServiceRoutes.StripPathPrefixMetadataKey)
            : service?.Service.StripPathPrefix == true ? ServiceRoutes.PathPrefixOf(service.Service) : null;
        var path = ForwardingPathPolicy.EffectivePath(context.Request.Path, prefix);
        if (service is null || !FreshAuthenticationPolicy.TryNormalizeRequest(context.Request, path, out var canonical))
        {
            Forbid(context);
            return;
        }
        var maxAge = FreshAuthenticationPolicy.MaxAge(service.Service, canonical, context.Request.Method);
        if (maxAge is null)
        {
            await next(context);
            return;
        }

        // A limited route can only be satisfied by a recent interactive cookie session; any other credential cannot prove its age,
        // and an on-behalf session (resolved after this check) would otherwise borrow the actor's freshness for the represented user.
        if ((context.Items[Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] is string selected && selected != CookieAuthenticationDefaults.AuthenticationScheme)
            || context.Request.Cookies.ContainsKey(Cookies.OnBehalf))
        {
            Forbid(context);
            return;
        }
        var session = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        SessionProvider.TryRead(context.User, session.Properties, out var scheme);

        // An OAuth provider can neither prove nor force when the user authenticated; no reauthentication can satisfy the limit.
        if (IsOAuthProvider(config, scheme))
        {
            FreshAuthenticationRequired(logger, context.Request.Method, RequestPathRedaction.Redact(context.Request.Path), service.Name);
            Forbid(context);
            return;
        }
        if (session.Succeeded && SessionAuthenticationTime.IsFresh(context.User, session.Properties, maxAge.Value, clock.GetUtcNow()))
        {
            await next(context);
            return;
        }
        Refuse(context, string.IsNullOrEmpty(scheme) ? null : scheme, maxAge.Value, service.Name);
    }

    [LoggerMessage(LogLevel.Information, "Fresh authentication required for {Method} {Path} on service {Service}")]
    static partial void FreshAuthenticationRequired(ILogger logger, string method, string path, string service);

    static bool IsOAuthProvider(C.AuthProxy config, string? scheme) =>
        !string.IsNullOrEmpty(scheme) && config.Authentication.OAuthProviders.Any(provider => OidcProviderScheme.FromName(provider.Name) == scheme);

    static void Forbid(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentLength = 0;
    }

    void Refuse(HttpContext context, string? scheme, TimeSpan maxAge, string service)
    {
        FreshAuthenticationRequired(logger, context.Request.Method, RequestPathRedaction.Redact(context.Request.Path), service);
        context.Response.Headers.CacheControl = "no-store";
        if (HttpMethods.IsGet(context.Request.Method) && context.IsDocumentNavigation())
        {
            context.Response.Redirect(FreshAuthenticationChallenge.Login(scheme, context.GetPathAndQuery(), maxAge));
            return;
        }

        // RFC 9470: a caller that is not a browser navigation cannot follow a login redirect, so it is told how recent
        // an authentication it needs; the operation is never replayed.
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = $"Bearer error=\"insufficient_user_authentication\", max_age=\"{(int)maxAge.TotalSeconds}\"";
    }
}
