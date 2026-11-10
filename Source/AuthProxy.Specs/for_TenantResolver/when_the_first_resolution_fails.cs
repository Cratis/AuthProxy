// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// An unusable identifier from the first resolution is logged but does not stop the next resolution.
/// </summary>
public class when_the_first_resolution_fails : a_tenant_resolver
{
    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(
            Resolution(C.TenantSourceIdentifierResolverType.Specified, new SpecifiedOptions { TenantId = "a b" }),
            Resolution(C.TenantSourceIdentifierResolverType.Default, new DefaultOptions { TenantId = "fallback" })),
        new SpecifiedSourceIdentifierStrategy(),
        new DefaultSourceIdentifierStrategy());

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_use_the_second_resolution() => _result.TenantId.ShouldEqual("fallback");
    [Fact] void should_report_the_strategy_of_the_second_resolution() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.Default);
    [Fact] void should_log_that_the_first_identifier_is_not_usable() => UnusableIdentifierWasLogged.ShouldBeTrue();
    [Fact] void should_not_log_that_no_strategy_resolved_a_tenant() => NoStrategyResolvedWasLogged.ShouldBeFalse();
}
