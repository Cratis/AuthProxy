// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_two_services_claim_the_same_host : given.a_service_routing_validator
{
    void Establish()
    {
        _services["one"] = Routable("billing.example.com");
        _services["two"] = Routable("BILLING.example.com:8443");
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_host() => _result.FailureMessage.ShouldContain("billing.example.com");
}
