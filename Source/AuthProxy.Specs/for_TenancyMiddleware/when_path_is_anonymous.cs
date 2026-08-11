// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware;

/// <summary>
/// An unauthenticated request to a declared anonymous path must still have its inbound identity headers
/// removed, and must be forwarded rather than refused for having no resolvable tenant.
/// <para>
/// The header strip is the property that makes declaring a path anonymous safe. A caller reaching an
/// anonymous path has no session, so anything it sends in <c>x-ms-client-principal*</c> or
/// <c>Tenant-ID</c> is unverified — the application's identity handler would build a principal straight
/// out of it. Because the request still travels through AuthProxy, the strip that runs for every other
/// request runs for this one too; that is the whole reason to solve this inside the proxy instead of
/// routing around it at the ingress, where those headers would arrive untouched.
/// </para>
/// </summary>
public class when_path_is_anonymous : Specification
{
    const string AnonymousPath = "/portal";

    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var configuration = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["test"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                    AnonymousPaths = [AnonymousPath],
                },
            },
            TenantResolutions = [new C.TenantResolution { Strategy = C.TenantSourceIdentifierResolverType.Selection }],
        };

        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(configuration);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>())
            .Returns(callInfo =>
            {
                callInfo[1] = string.Empty;
                return false;
            });

        _middleware = new TenancyMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config,
            tenantResolver,
            Substitute.For<ITenantVerifier>(),
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = AnonymousPath;
        _context.Request.Headers[Headers.Principal] = "forged-principal";
        _context.Request.Headers[Headers.PrincipalId] = "forged-id";
        _context.Request.Headers[Headers.PrincipalName] = "forged-name";
        _context.Request.Headers[Headers.PrincipalNameExtended] = "UTF-8''forged-name";
        _context.Request.Headers[Headers.TenantId] = "forged-tenant";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_strip_the_inbound_principal() => _context.Request.Headers.ContainsKey(Headers.Principal).ShouldBeFalse();
    [Fact] void should_strip_the_inbound_principal_id() => _context.Request.Headers.ContainsKey(Headers.PrincipalId).ShouldBeFalse();
    [Fact] void should_strip_the_inbound_principal_name() => _context.Request.Headers.ContainsKey(Headers.PrincipalName).ShouldBeFalse();
    [Fact] void should_strip_the_inbound_extended_principal_name() => _context.Request.Headers.ContainsKey(Headers.PrincipalNameExtended).ShouldBeFalse();
    [Fact] void should_strip_the_inbound_tenant_id() => _context.Request.Headers.ContainsKey(Headers.TenantId).ShouldBeFalse();
    [Fact] void should_not_refuse_the_request_for_having_no_tenant() => _nextCalled.ShouldBeTrue();
}
