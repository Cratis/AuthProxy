// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// A direct strategy never consults the tenant map, so a tenant listing the identifier does not rescue it.
/// </summary>
public class when_specified_identifier_is_not_usable : a_tenant_resolver
{
    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(
            new C.Tenants { ["tenant-one"] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["a b"] } },
            Resolution(C.TenantSourceIdentifierResolverType.Specified, new SpecifiedOptions { TenantId = "a b" })),
        new SpecifiedSourceIdentifierStrategy());

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_report_no_strategy() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.None);
    [Fact] void should_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeTrue();
    [Fact] void should_log_that_no_strategy_resolved_a_tenant() => NoStrategyResolvedWasLogged.ShouldBeTrue();
}
