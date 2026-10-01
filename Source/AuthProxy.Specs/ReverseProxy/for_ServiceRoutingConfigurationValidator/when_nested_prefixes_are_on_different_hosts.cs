// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_nested_prefixes_are_on_different_hosts : given.a_service_routing_validator
{
    void Establish()
    {
        _services["one"] = Routable("one.example.com");
        _services["one"].PathPrefix = "/reports";
        _services["two"] = Routable("two.example.com");
        _services["two"].PathPrefix = "/reports";
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
