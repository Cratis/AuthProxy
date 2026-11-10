// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_no_strategy_is_registered_for_the_configured_type : a_tenant_resolver
{
    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(Resolution(C.TenantSourceIdentifierResolverType.Specified, new SpecifiedOptions { TenantId = "tenant-one" })),
        new DefaultSourceIdentifierStrategy());

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _result.TenantId.ShouldEqual(string.Empty);
    [Fact] void should_log_that_no_strategy_resolved_a_tenant() => NoStrategyResolvedWasLogged.ShouldBeTrue();
    [Fact] void should_not_log_that_the_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeFalse();
}
