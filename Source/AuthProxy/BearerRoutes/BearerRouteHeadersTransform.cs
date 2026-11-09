// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;
using Microsoft.Net.Http.Headers;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Replaces every identity header of a bearer-route request with what AuthProxy vouches for.
/// </summary>
/// <remarks>
/// Every inbound copy of a header a backend trusts is removed first — the principal set, <c language="text">Tenant-ID</c>,
/// and the token client and scope headers — so a caller cannot add to what the token says. The
/// <c language="text">Cookie</c> header is removed because a bearer route does not use browser sessions, and a backend must
/// not be able to fall back to one. <c language="text">Authorization</c> is removed unless the route asks for it: the
/// backend receives the principal AuthProxy vouches for, not the credential.
/// </remarks>
public class BearerRouteHeadersTransform : RequestTransform
{
    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        var headers = context.ProxyRequest.Headers;
        SpoofableHeaders.Strip(headers);
        headers.Remove(Headers.ServiceId);
        headers.Remove(Headers.LegacyServiceId);
        headers.Remove(HeaderNames.Cookie);

        var identity = context.HttpContext.Items.TryGetValue(BearerRouteDefaults.ForwardedIdentityItemKey, out var item)
            ? item as BearerForwardedIdentity
            : null;

        var passThrough = context.HttpContext.Items.TryGetValue(BearerRouteDefaults.PassThroughAuthorizationItemKey, out var marker) && marker is true;
        if (identity?.ForwardAuthorizationHeader != true && !passThrough)
        {
            headers.Authorization = null;
        }

        if (identity is null)
        {
            return ValueTask.CompletedTask;
        }

        context.ProxyRequest.SetMicrosoftIdentityHeaders(identity.Principal);
        var tenantId = HeaderValue.ToTransportValue(identity.TenantId);
        headers.TryAddWithoutValidation(Headers.TenantId, tenantId);
        headers.TryAddWithoutValidation(Headers.LegacyTenantId, tenantId);
        if (identity.Scopes.Count > 0)
        {
            headers.TryAddWithoutValidation(Headers.TokenScope, HeaderValue.ToTransportValue(string.Join(' ', identity.Scopes)));
        }

        if (!string.IsNullOrWhiteSpace(identity.ClientId))
        {
            headers.TryAddWithoutValidation(Headers.TokenClientId, HeaderValue.ToTransportValue(identity.ClientId));
        }

        if (context.HttpContext.Items[BearerRouteDefaults.ServiceItemKey] is string service)
        {
            var value = HeaderValue.ToTransportValue(service);
            context.ProxyRequest.Headers.TryAddWithoutValidation(Headers.ServiceId, value);
            context.ProxyRequest.Headers.TryAddWithoutValidation(Headers.LegacyServiceId, value);
        }

        return ValueTask.CompletedTask;
    }
}
