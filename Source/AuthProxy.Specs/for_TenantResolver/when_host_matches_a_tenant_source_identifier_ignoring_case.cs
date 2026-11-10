// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_host_matches_a_tenant_source_identifier_ignoring_case : a_tenant_resolver
{
    void Establish()
    {
        _context.Request.Host = new HostString("Acme.Example.com");
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["acme-tenant"] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["acme.example.COM"] } },
                Resolution(C.TenantSourceIdentifierResolverType.Host)),
            new HostSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_matching_tenant() => _result.TenantId.ShouldEqual("acme-tenant");
}
