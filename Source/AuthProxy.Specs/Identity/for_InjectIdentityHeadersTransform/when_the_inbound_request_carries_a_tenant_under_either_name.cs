// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Identity.for_InjectIdentityHeadersTransform;

/// <summary>
/// The proxy request begins as a copy of the inbound one, so the transform is the last place a header the
/// caller sent can be removed before it reaches a backend. It removes the tenant under both names whether
/// or not the proxy resolved one: a request with no resolved tenant must reach the backend with none, not
/// with the caller's, and a request with one must carry it only as <c language="text">x-cratis-tenant-id</c> and not also under
/// the legacy name earlier releases used.
/// </summary>
public class when_the_inbound_request_carries_a_tenant_under_either_name : Specification
{
    const string ResolvedTenant = "resolved-tenant";

    RequestTransformContext _withoutResolvedTenant;
    RequestTransformContext _withResolvedTenant;

    void Establish()
    {
        _withoutResolvedTenant = ContextFor(resolvedTenant: null);
        _withResolvedTenant = ContextFor(ResolvedTenant);
    }

    async Task Because()
    {
        var transform = new InjectIdentityHeadersTransform();
        await transform.ApplyAsync(_withoutResolvedTenant);
        await transform.ApplyAsync(_withResolvedTenant);
    }

    [Fact] void should_send_no_tenant_when_none_was_resolved() =>
        _withoutResolvedTenant.ProxyRequest.Headers.Contains(Headers.TenantId).ShouldBeFalse();
    [Fact] void should_send_no_legacy_tenant_when_none_was_resolved() =>
        _withoutResolvedTenant.ProxyRequest.Headers.Contains(Headers.LegacyTenantId).ShouldBeFalse();
    [Fact] void should_send_no_unknown_principal_header_when_none_was_resolved() =>
        _withoutResolvedTenant.ProxyRequest.Headers.Contains("x-ms-client-principal-idp").ShouldBeFalse();
    [Fact] void should_send_only_the_resolved_tenant() =>
        _withResolvedTenant.ProxyRequest.Headers.GetValues(Headers.TenantId).Single().ShouldEqual(ResolvedTenant);
    [Fact] void should_not_also_send_the_legacy_tenant() =>
        _withResolvedTenant.ProxyRequest.Headers.Contains(Headers.LegacyTenantId).ShouldBeFalse();
    [Fact] void should_send_no_unknown_principal_header_when_a_tenant_was_resolved() =>
        _withResolvedTenant.ProxyRequest.Headers.Contains("x-ms-client-principal-idp").ShouldBeFalse();

    static RequestTransformContext ContextFor(string? resolvedTenant)
    {
        var httpContext = new DefaultHttpContext();
        if (resolvedTenant is not null)
        {
            httpContext.Items[TenancyMiddleware.TenantIdItemKey] = resolvedTenant;
        }

        var context = new RequestTransformContext
        {
            HttpContext = httpContext,
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://service.local/api/test")
        };
        context.ProxyRequest.Headers.TryAddWithoutValidation("x-cratis-tenant-id", "victim-tenant");
        context.ProxyRequest.Headers.TryAddWithoutValidation("Tenant-ID", "victim-tenant-legacy");
        context.ProxyRequest.Headers.TryAddWithoutValidation("x-ms-client-principal-idp", "aad");

        return context;
    }
}
