// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// A YARP <see cref="RequestTransform"/> that injects the three Microsoft Identity Platform
/// headers (<c language="text">x-ms-client-principal</c>, <c language="text">x-ms-client-principal-id</c>,
/// <c language="text">x-ms-client-principal-name</c>) and both tenant headers into every
/// proxied request, based on the authenticated user and the resolved tenant.
/// </summary>
/// <remarks>
/// Every inbound copy is removed first — every <c language="text">x-ms-client-principal*</c> header, including the
/// <c language="text">x-ms-client-principal-name*</c> sibling a caller could otherwise use to tell a backend a different name
/// than the one the proxy vouched for, and the tenant under both <c language="text">x-cratis-tenant-id</c> and the legacy
/// <c language="text">Tenant-ID</c>. A request with no resolved tenant reaches the backend with no tenant header at all.
/// </remarks>
public class InjectIdentityHeadersTransform : RequestTransform
{
    /// <inheritdoc/>
    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        var httpContext = context.HttpContext;

        // The proxy request starts as a copy of the inbound one. Strip it again here, rather than rely only on
        // the tenancy middleware having run, so nothing a caller sent survives whatever path led here.
        SpoofableHeaders.Strip(context.ProxyRequest.Headers);

        // Only a bearer route vouches for these, and bearer routes are never forwarded through here.
        context.ProxyRequest.Headers.Remove(Headers.TokenClientId);
        context.ProxyRequest.Headers.Remove(Headers.TokenScope);

        var principal = httpContext.BuildClientPrincipal();
        if (principal is not null)
        {
            context.ProxyRequest.SetMicrosoftIdentityHeaders(principal);
        }

        // Forward the resolved tenant if it was set by the tenancy middleware.
        if (httpContext.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var tenantId)
            && tenantId is string tid && !string.IsNullOrWhiteSpace(tid))
        {
            var tenant = HeaderValue.ToTransportValue(tid);
            context.ProxyRequest.Headers.Add(Headers.TenantId, tenant);
            context.ProxyRequest.Headers.Add(Headers.LegacyTenantId, tenant);
        }

        // Both backend contracts identify the destination, not a caller-supplied selector that may have
        // lost to an anonymous-path, query, or single-service catch-all route.
        var service = ServiceSelection.FromRoute(httpContext);
        context.ProxyRequest.Headers.Remove(Headers.ServiceId);
        context.ProxyRequest.Headers.Remove(Headers.LegacyServiceId);
        if (!string.IsNullOrWhiteSpace(service))
        {
            var serviceId = HeaderValue.ToTransportValue(service);
            context.ProxyRequest.Headers.Add(Headers.ServiceId, serviceId);
            context.ProxyRequest.Headers.Add(Headers.LegacyServiceId, serviceId);
        }

        return ValueTask.CompletedTask;
    }
}
