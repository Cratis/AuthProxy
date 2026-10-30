// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator;

public class when_the_service_name_cannot_name_a_cookie : given.a_validator
{
    void Because() => _result = Validate(Backend(Sticky(), name: "core api"));

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_service() => _result.FailureMessage.ShouldContain("Cratis:AuthProxy:Services:core api");
}
