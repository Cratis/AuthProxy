// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Transforms;
using C = Cratis.AuthProxy.Configuration;

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

        var service = ServiceSelection.FromRoute(httpContext);
        var principal = AnonymousPaths.PassesCallerAuthorization(httpContext) ? null : httpContext.BuildClientPrincipal();
        if (principal is not null)
        {
            SetPrincipalHeaders(context, principal);
        }

        // During an on-behalf session the principal above is the represented user. The actor and the signed assertion
        // are added by OnBehalfForwardTransform, last, once the path the backend receives is final.
        if (httpContext.TryGetOnBehalf(out _))
        {
            context.ProxyRequest.Headers.Authorization = null;
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

    static void SetPrincipalHeaders(RequestTransformContext context, ClientPrincipal principal)
    {
        if (ForwardsSessionContext(context.HttpContext))
        {
            principal = principal.WithSessionContext(context.HttpContext);
        }
        context.ProxyRequest.SetMicrosoftIdentityHeaders(principal);
    }

    static bool ForwardsSessionContext(HttpContext context)
    {
        var service = ServiceSelection.FromRoute(context);
        var config = context.RequestServices?.GetService<IOptionsMonitor<C.AuthProxy>>()?.CurrentValue;
        return service is not null && config is not null
            && config.Services.TryGetValue(service, out var selected) && selected.ForwardSessionContext;
    }
}
