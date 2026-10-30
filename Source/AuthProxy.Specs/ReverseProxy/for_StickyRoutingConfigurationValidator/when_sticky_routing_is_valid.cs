// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator;

public class when_sticky_routing_is_valid : given.a_validator
{
    void Because() => _result = Validate(Backend(Sticky()));

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
