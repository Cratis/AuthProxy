// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.Ingress.for_TenancyMiddleware;

public class when_request_has_spoofed_identity_headers : Specification
{
    TenancyMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var config = new IngressConfig();
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<Guid>()).Returns(true);

        var identityResolver = Substitute.For<IIdentityDetailsResolver>();
        identityResolver.Resolve(Arg.Any<HttpContext>(), Arg.Any<Identity.ClientPrincipal>(), Arg.Any<Guid>()).Returns(Task.FromResult(new IdentityProviderResult("user-id", "user-name", true, true, [], null!)));

        _middleware = new TenancyMiddleware(
            _ => Task.CompletedTask,
            optionsMonitor,
            tenantResolver,
            Substitute.For<ITenantVerifier>(),
            identityResolver,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Headers[Headers.Principal] = "spoofed-principal";
        _context.Request.Headers[Headers.PrincipalId] = "spoofed-id";
        _context.Request.Headers[Headers.PrincipalName] = "spoofed-name";
        _context.Request.Headers[Headers.TenantId] = "spoofed-tenant";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_strip_the_principal_header() => Assert.False(_context.Request.Headers.ContainsKey(Headers.Principal));
    [Fact] void should_strip_the_principal_id_header() => Assert.False(_context.Request.Headers.ContainsKey(Headers.PrincipalId));
    [Fact] void should_strip_the_principal_name_header() => Assert.False(_context.Request.Headers.ContainsKey(Headers.PrincipalName));
    [Fact] void should_strip_the_tenant_id_header() => Assert.False(_context.Request.Headers.ContainsKey(Headers.TenantId));
}
