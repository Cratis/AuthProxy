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
        headers.Remove(Headers.Principal);
        headers.Remove(Headers.PrincipalId);
        headers.Remove(Headers.PrincipalName);
        headers.Remove(Headers.PrincipalNameExtended);
        headers.Remove(Headers.TenantId);
        headers.Remove(Headers.TokenClientId);
        headers.Remove(Headers.TokenScope);
        headers.Remove(HeaderNames.Cookie);

        var identity = context.HttpContext.Items.TryGetValue(BearerRouteDefaults.ForwardedIdentityItemKey, out var item)
            ? item as BearerForwardedIdentity
            : null;

        if (identity?.ForwardAuthorizationHeader != true)
        {
            headers.Authorization = null;
        }

        if (identity is null)
        {
            return ValueTask.CompletedTask;
        }

        context.ProxyRequest.SetMicrosoftIdentityHeaders(identity.Principal);
        headers.TryAddWithoutValidation(Headers.TenantId, HeaderValue.ToTransportValue(identity.TenantId));
        if (identity.Scopes.Count > 0)
        {
            headers.TryAddWithoutValidation(Headers.TokenScope, HeaderValue.ToTransportValue(string.Join(' ', identity.Scopes)));
        }

        if (!string.IsNullOrWhiteSpace(identity.ClientId))
        {
            headers.TryAddWithoutValidation(Headers.TokenClientId, HeaderValue.ToTransportValue(identity.ClientId));
        }

        return ValueTask.CompletedTask;
    }
}
