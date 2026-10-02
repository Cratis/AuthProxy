// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Authentication.Cookies;
using Yarp.ReverseProxy.Model;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Puts the signed-in user's access token for a service's audience on requests proxied to that service's backend.
/// </summary>
/// <remarks>
/// Runs in the reverse-proxy pipeline, after a route and cluster are selected, so it knows exactly which service and
/// endpoint the request goes to. It acts only on requests authenticated by the AuthProxy session cookie and routed
/// to the backend of a service that declares <see cref="C.Service.AccessToken"/>. Machine callers authenticated by a
/// bearer token keep their own <c language="text">Authorization</c> header, and anonymous paths are forwarded as they are.
/// When no token can be obtained the request is refused with <c language="text">401</c>, never forwarded without the token
/// the backend expects. A configuration reload snapshot whose destinations do not match the token policy is refused
/// with <c language="text">503</c> before obtaining a token.
/// </remarks>
/// <param name="next">The next middleware in the proxy pipeline.</param>
/// <param name="logger">The <see cref="ILogger"/> for diagnostics.</param>
public class AccessTokenForwardingMiddleware(
    RequestDelegate next,
    ILogger<AccessTokenForwardingMiddleware> logger)
{
    /// <summary>
    /// Handles the request.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="tokens">The <see cref="IUserAccessTokens"/> obtaining tokens.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context, IUserAccessTokens tokens)
    {
        var proxy = context.Features.Get<IReverseProxyFeature>();
        if (proxy is null
            || proxy.Route.Config.AuthorizationPolicy == MicroserviceReverseProxyConfigProvider.AnonymousAuthorizationPolicy
            || !TryGetAccessToken(proxy, out var serviceName, out var accessToken)
            || !IsSessionRequest(context))
        {
            await next(context);
            return;
        }

        // YARP publishes the cluster model and destinations separately. Never acquire a token for a policy
        // paired with destinations from another binding, even in the short interval during a reload.
        if (!HasBoundDestinations(proxy))
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }

        var result = UserTokenSessions.Of(context) is { } sessionId
            ? await tokens.GetFor(sessionId, accessToken, context.RequestAborted)
            : UserAccessTokenResult.Failed(UserAccessTokenFailure.NoRefreshToken);

        if (!result.Succeeded)
        {
            logger.AccessTokenUnavailable(serviceName, result.Failure);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        context.Request.Headers.Authorization = $"Bearer {result.Token}";
        await next(context);
    }

    static bool TryGetAccessToken(IReverseProxyFeature proxy, out string serviceName, out C.ServiceAccessToken accessToken)
    {
        serviceName = string.Empty;
        accessToken = default!;

        var metadata = proxy.Cluster.Config.Metadata;
        if (metadata is null
            || !metadata.TryGetValue(MicroserviceReverseProxyConfigProvider.ServiceMetadataKey, out var key)
            || !metadata.TryGetValue(MicroserviceReverseProxyConfigProvider.EndpointMetadataKey, out var endpoint)
            || endpoint != MicroserviceReverseProxyConfigProvider.BackendEndpoint
            || !metadata.TryGetValue(MicroserviceReverseProxyConfigProvider.AccessTokenMetadataKey, out var policy))
        {
            return false;
        }

        serviceName = key;
        accessToken = JsonSerializer.Deserialize<C.ServiceAccessToken>(policy)!;
        return true;
    }

    static bool HasBoundDestinations(IReverseProxyFeature proxy) =>
        proxy.Cluster.Config.Metadata!.TryGetValue(MicroserviceReverseProxyConfigProvider.DestinationMetadataKey, out var destinationId)
        && proxy.AvailableDestinations.Count > 0
        && proxy.AllDestinations.Count > 0
        && proxy.AvailableDestinations.All(destination => string.Equals(destination.DestinationId, destinationId, StringComparison.Ordinal))
        && proxy.AllDestinations.All(destination => string.Equals(destination.DestinationId, destinationId, StringComparison.Ordinal));

    static bool IsSessionRequest(HttpContext context) =>
        context.User.Identity?.IsAuthenticated == true
        && string.Equals(
            context.Items[Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] as string,
            CookieAuthenticationDefaults.AuthenticationScheme,
            StringComparison.Ordinal);
}
