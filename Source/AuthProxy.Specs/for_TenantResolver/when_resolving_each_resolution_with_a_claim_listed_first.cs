// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// The first resolution that resolves wins for ordinary tenant resolution, so a claim listed first hides the host.
/// Resolving each resolution on its own sees both.
/// </summary>
public class when_resolving_each_resolution_with_a_claim_listed_first : Specification
{
    const string ClaimTenant = "55555555-5555-5555-5555-555555555555";
    const string HostTenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    TenantResolver _resolver;
    DefaultHttpContext _context;
    TenantResolutionResult[] _results;
    TenantResolutionResult _first;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Tenants = new C.Tenants
            {
                [ClaimTenant] = new C.Tenant { Name = "Support", SourceIdentifiers = ["support"] },
                [HostTenant] = new C.Tenant { Name = "Acme", Domains = ["acme.example.com"] },
            },
            TenantResolutions =
            [
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.Claim,
                    Options = new ClaimOptions { ClaimType = "tenant_claim" },
                },
                new C.TenantResolution { Strategy = C.TenantSourceIdentifierResolverType.Host },
            ],
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("tenant_claim", "support")], "aad")) };
        _context.Request.Host = new HostString("acme.example.com");

        _resolver = new TenantResolver(
            optionsMonitor,
            [new ClaimSourceIdentifierStrategy(), new HostSourceIdentifierStrategy()],
            Substitute.For<ILogger<TenantResolver>>());
    }

    void Because()
    {
        _results = [.. _resolver.ResolveEach(_context)];
        _resolver.TryResolve(_context, out _first);
    }

    [Fact] void should_resolve_the_claim() => _results.ShouldContain(new TenantResolutionResult(ClaimTenant, C.TenantSourceIdentifierResolverType.Claim));
    [Fact] void should_resolve_the_host_as_well() => _results.ShouldContain(new TenantResolutionResult(HostTenant, C.TenantSourceIdentifierResolverType.Host));
    [Fact] void should_still_let_the_first_resolution_win_for_ordinary_resolution() => _first.TenantId.ShouldEqual(ClaimTenant);
}
