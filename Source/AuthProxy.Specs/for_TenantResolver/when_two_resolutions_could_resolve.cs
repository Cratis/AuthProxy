// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_two_resolutions_could_resolve : a_tenant_resolver
{
    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(
            Resolution(C.TenantSourceIdentifierResolverType.Default, new DefaultOptions { TenantId = "second" }),
            Resolution(C.TenantSourceIdentifierResolverType.Specified, new SpecifiedOptions { TenantId = "first" })),
        new SpecifiedSourceIdentifierStrategy(),
        new DefaultSourceIdentifierStrategy());

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_use_the_first_configured_resolution() => _result.TenantId.ShouldEqual("second");
    [Fact] void should_report_the_strategy_of_the_first_configured_resolution() => _result.Strategy.ShouldEqual(C.TenantSourceIdentifierResolverType.Default);
    [Fact] void should_not_log_a_warning() => _logger.Levels.ShouldBeEmpty();
}
