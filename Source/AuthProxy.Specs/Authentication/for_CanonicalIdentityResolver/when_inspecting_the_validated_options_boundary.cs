// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver;

/// <summary>
/// Specifies that canonical identity resolution consumes the independently validated authentication options boundary.
/// </summary>
public class when_inspecting_the_validated_options_boundary : Specification
{
    bool _hasAuthenticationOptionsConstructor;

    void Because() => _hasAuthenticationOptionsConstructor = typeof(CanonicalIdentityResolver)
        .GetConstructor([typeof(IOptionsMonitor<C.Authentication>)]) is not null;

    [Fact] void should_depend_on_the_authentication_options_monitor() => _hasAuthenticationOptionsConstructor.ShouldBeTrue();
}
