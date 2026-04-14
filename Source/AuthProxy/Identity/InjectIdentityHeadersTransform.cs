// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.Ingress.Identity;

/// <summary>
/// A YARP <see cref="RequestTransform"/> that injects the three Microsoft Identity Platform
/// headers (<c>x-ms-client-principal</c>, <c>x-ms-client-principal-id</c>,
/// <c>x-ms-client-principal-name</c>) and the <c>Tenant-ID</c> header into every
/// proxied request, based on the authenticated user and the resolved tenant.
/// </summary>
public class InjectIdentityHeadersTransform : RequestTransform
{
    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        var httpContext = context.HttpContext;

        var principal = httpContext.BuildClientPrincipal();
        if (principal is not null)
        {
            context.ProxyRequest.Headers.Remove(Headers.Principal);
            context.ProxyRequest.Headers.Remove(Headers.PrincipalId);
            context.ProxyRequest.Headers.Remove(Headers.PrincipalName);
            context.ProxyRequest.Headers.Add(Headers.Principal, principal.ToBase64());
            context.ProxyRequest.Headers.Add(Headers.PrincipalId, principal.UserId);
            context.ProxyRequest.Headers.Add(Headers.PrincipalName, principal.UserDetails);
        }

        // Forward the resolved Tenant-ID if it was set by the tenancy middleware.
        if (httpContext.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var tenantId)
            && tenantId is Guid tid && tid != Guid.Empty)
        {
            context.ProxyRequest.Headers.Remove(Headers.TenantId);
            context.ProxyRequest.Headers.Add(Headers.TenantId, tid.ToString());
        }

        return ValueTask.CompletedTask;
    }
}
