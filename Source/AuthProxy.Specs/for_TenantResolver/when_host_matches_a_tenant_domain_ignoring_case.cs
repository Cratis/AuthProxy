// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_host_matches_a_tenant_domain_ignoring_case : a_tenant_resolver
{
    void Establish()
    {
        _context.Request.Host = new HostString("acme.example.com");
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants
                {
                    ["first-tenant"] = new C.Tenant { Name = "First", Domains = ["first.example.com"] },
                    ["second-tenant"] = new C.Tenant { Name = "Second", Domains = ["ACME.Example.COM"] }
                },
                Resolution(C.TenantSourceIdentifierResolverType.Host)),
            new HostSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_matching_tenant() => _result.TenantId.ShouldEqual("second-tenant");
    [Fact] void should_report_the_host_strategy() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.Host);
}
