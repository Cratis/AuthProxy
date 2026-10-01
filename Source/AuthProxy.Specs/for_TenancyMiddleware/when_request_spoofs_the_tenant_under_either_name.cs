// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware;

/// <summary>
/// Arc resolves its tenant from <c language="text">x-cratis-tenant-id</c> by default, and earlier AuthProxy releases forwarded
/// the tenant as <c language="text">Tenant-ID</c>. Stripping only the second left the first open, so an Arc application behind
/// the proxy on its default tenancy settings took its tenant — and with it the Chronicle namespace and the
/// tenant-scoped read models — from whatever the client chose to send. A client must not be able to assert a
/// tenant under either name, however the header is cased, and the only tenant that can reach the backend is
/// the one the proxy resolved.
/// <para>
/// Identity headers are removed by their shared <c language="text">x-ms-client-principal</c> prefix, so a header the proxy
/// never writes but a backend might read, such as <c language="text">x-ms-client-principal-idp</c>, goes the same way.
/// </para>
/// </summary>
public class when_request_spoofs_the_tenant_under_either_name : Specification
{
    const string ResolvedTenant = "resolved-tenant";

    TenancyMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var config = new C.AuthProxy();
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>())
            .Returns(call =>
            {
                call[1] = ResolvedTenant;
                return true;
            });

        var tenantVerifier = Substitute.For<ITenantVerifier>();
        tenantVerifier.VerifyAsync(Arg.Any<string>()).Returns(Task.FromResult(true));

        _middleware = new TenancyMiddleware(
            _ => Task.CompletedTask,
            optionsMonitor,
            tenantResolver,
            tenantVerifier,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Headers["x-cratis-tenant-id"] = "victim-tenant";
        _context.Request.Headers["X-CRATIS-TENANT-ID"] = "victim-tenant-upper";
        _context.Request.Headers["Tenant-ID"] = "victim-tenant-legacy";
        _context.Request.Headers["tenant-id"] = "victim-tenant-legacy-lower";
        _context.Request.Headers["x-ms-client-principal-idp"] = "aad";
        _context.Request.Headers["X-MS-CLIENT-PRINCIPAL-ROLES"] = "Administrator";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_strip_the_tenant_header_arc_resolves_by_default() => _context.Request.Headers.ContainsKey("x-cratis-tenant-id").ShouldBeFalse();
    [Fact] void should_strip_the_legacy_tenant_header() => _context.Request.Headers.ContainsKey("Tenant-ID").ShouldBeFalse();
    [Fact] void should_strip_every_principal_header_whatever_its_suffix() =>
        _context.Request.Headers.Keys.Any(_ => _.StartsWith("x-ms-client-principal", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
    [Fact] void should_keep_the_resolved_tenant_for_the_proxy_to_forward() => _context.Items[TenancyMiddleware.TenantIdItemKey].ShouldEqual(ResolvedTenant);
}
