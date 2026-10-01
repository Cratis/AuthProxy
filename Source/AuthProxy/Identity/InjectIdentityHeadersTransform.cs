// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// A YARP <see cref="RequestTransform"/> that injects the three Microsoft Identity Platform
/// headers (<c language="text">x-ms-client-principal</c>, <c language="text">x-ms-client-principal-id</c>,
/// <c language="text">x-ms-client-principal-name</c>) and the <c language="text">x-cratis-tenant-id</c> header into every
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

        var principal = httpContext.BuildClientPrincipal();
        if (principal is not null)
        {
            context.ProxyRequest.SetMicrosoftIdentityHeaders(principal);
        }

        // Forward the resolved tenant if it was set by the tenancy middleware.
        if (httpContext.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var tenantId)
            && tenantId is string tid && !string.IsNullOrWhiteSpace(tid))
        {
            context.ProxyRequest.Headers.Add(Headers.TenantId, HeaderValue.ToTransportValue(tid));
        }

        return ValueTask.CompletedTask;
    }
}
