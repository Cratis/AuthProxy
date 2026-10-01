// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_one_prefix_is_nested_in_another : given.a_service_routing_validator
{
    void Establish()
    {
        _services["one"] = Routable();
        _services["one"].PathPrefix = "/reports";
        _services["two"] = Routable();
        _services["two"].PathPrefix = "/reports/archive";
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
}
