// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Decides whether the <c language="text">Authorization</c> header a caller sent reaches a service, following
/// <see cref="C.Service.CallerAuthorizationHeader"/>.
/// </summary>
/// <remarks>
/// In order: a header AuthProxy wrote itself is kept; the bearer token of a caller AuthProxy authenticated is kept; on a
/// request authenticated by the session the caller's header is removed unless the service forwards it; on any other
/// request it is kept unless the service strips it.
/// </remarks>
public class CallerAuthorizationHeaderTransform : RequestTransform
{
    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        var http = context.HttpContext;
        if (http.Items.TryGetValue(AccessTokenForwardingMiddleware.ForwardedItemKey, out var forwarded) && forwarded is true)
        {
            return ValueTask.CompletedTask;
        }

        var scheme = http.Items[Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] as string;
        var authenticated = http.User.Identity?.IsAuthenticated == true;
        if (authenticated && (scheme == JwtBearerDefaults.AuthenticationScheme || scheme == ClientCredentialsDefaults.AuthenticationScheme))
        {
            return ValueTask.CompletedTask;
        }

        var setting = SettingOf(http);
        var sessionRequest = authenticated && string.Equals(scheme, CookieAuthenticationDefaults.AuthenticationScheme, StringComparison.Ordinal);
        var remove = sessionRequest
            ? setting != C.CallerAuthorizationHeaderForwarding.Forward
            : setting == C.CallerAuthorizationHeaderForwarding.Strip;

        if (remove)
        {
            context.ProxyRequest.Headers.Authorization = null;
        }

        return ValueTask.CompletedTask;
    }

    static C.CallerAuthorizationHeaderForwarding SettingOf(HttpContext context) =>
        context.Features.Get<IReverseProxyFeature>()?.Cluster.Config.Metadata is { } metadata
        && metadata.TryGetValue(MicroserviceReverseProxyConfigProvider.CallerAuthorizationHeaderMetadataKey, out var value)
        && Enum.TryParse<C.CallerAuthorizationHeaderForwarding>(value, out var setting)
            ? setting
            : C.CallerAuthorizationHeaderForwarding.Default;
}
