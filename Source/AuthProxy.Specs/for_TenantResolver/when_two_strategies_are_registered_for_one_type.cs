// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_two_strategies_are_registered_for_one_type : a_tenant_resolver
{
    void Establish() => _resolver = CreateResolver(
        ConfigurationOf(Resolution(C.TenantSourceIdentifierResolverType.Specified, new SpecifiedOptions())),
        new FixedIdentifierStrategy(C.TenantSourceIdentifierResolverType.Specified, "first-registered"),
        new FixedIdentifierStrategy(C.TenantSourceIdentifierResolverType.Specified, "second-registered"));

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_use_the_first_registered_strategy() => _result.TenantId.ShouldEqual("first-registered");
}
