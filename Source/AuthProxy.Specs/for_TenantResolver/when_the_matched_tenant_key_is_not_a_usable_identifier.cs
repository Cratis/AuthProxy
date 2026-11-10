// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_the_matched_tenant_key_is_not_a_usable_identifier : a_tenant_resolver
{
    void Establish()
    {
        _context.Request.Host = new HostString("acme.example.com");
        _resolver = CreateResolver(
            ConfigurationOf(
                new C.Tenants { ["bad key"] = new C.Tenant { Name = "Acme", Domains = ["acme.example.com"] } },
                Resolution(C.TenantSourceIdentifierResolverType.Host)),
            new HostSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeTrue();
}
