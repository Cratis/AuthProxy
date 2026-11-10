// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// The default strategy does not trim, so a whitespace identifier reaches the resolver. It is rejected as blank
/// (not as unusable) and the tenant map is not consulted even when a tenant lists it.
/// </summary>
public class when_default_identifier_is_whitespace : a_tenant_resolver
{
    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(
            new C.Tenants { ["tenant-one"] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["  "] } },
            Resolution(C.TenantSourceIdentifierResolverType.Default, new DefaultOptions { TenantId = "  " })),
        new DefaultSourceIdentifierStrategy());

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_not_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeFalse();
    [Fact] void should_log_that_no_strategy_resolved_a_tenant() => NoStrategyResolvedWasLogged.ShouldBeTrue();
}
