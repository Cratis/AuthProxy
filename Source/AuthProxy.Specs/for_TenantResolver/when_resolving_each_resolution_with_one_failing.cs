// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

/// <summary>
/// Every resolution runs on its own: a failing one is skipped and does not short-circuit the others.
/// </summary>
public class when_resolving_each_resolution_with_one_failing : a_tenant_resolver
{
    TenantResolutionResult[] _results;

    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(
            Resolution(C.TenantSourceIdentifierResolverType.Specified, new SpecifiedOptions { TenantId = "a b" }),
            Resolution(C.TenantSourceIdentifierResolverType.Default, new DefaultOptions { TenantId = "first-ok" }),
            Resolution(C.TenantSourceIdentifierResolverType.Selection)),
        new SpecifiedSourceIdentifierStrategy(),
        new DefaultSourceIdentifierStrategy(),
        new SelectionSourceIdentifierStrategy());

    void Because() => _results = [.. _resolver.ResolveEach(_context)];

    [Fact] void should_return_only_the_resolutions_that_succeeded() => _results.ShouldEqual([new TenantResolutionResult("first-ok", C.TenantSourceIdentifierResolverType.Default)]);
    [Fact] void should_log_that_the_unusable_identifier_was_ignored() => UnusableIdentifierWasLogged.ShouldBeTrue();
    [Fact] void should_not_log_that_no_strategy_resolved_a_tenant() => NoStrategyResolvedWasLogged.ShouldBeFalse();
}
