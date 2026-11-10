// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// An unmatched host never falls back to a tenant.
/// </summary>
public class when_host_matches_no_tenant : a_tenant_resolver
{
    void Establish()
    {
        _context.Request.Host = new HostString("unknown.example.com");
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["acme-tenant"] = new C.Tenant { Name = "Acme", Domains = ["acme.example.com"] } },
                Resolution(C.TenantSourceIdentifierResolverType.Host)),
            new HostSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_report_no_strategy() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.None);
}
