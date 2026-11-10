// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_host_is_empty : a_tenant_resolver
{
    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(
            new C.Tenants { ["acme-tenant"] = new C.Tenant { Name = "Acme", Domains = [string.Empty] } },
            Resolution(C.TenantSourceIdentifierResolverType.Host)),
        new HostSourceIdentifierStrategy());

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_not_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeFalse();
}
