// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_services_declare_equivalent_unicode_and_punycode_hosts : given.a_service_routing_validator
{
    void Establish()
    {
        _services["one"] = Routable("bücher.example");
        _services["two"] = Routable("xn--bcher-kva.example:8443");
    }

    void Because() => Validate();

    [Fact] void should_refuse_the_overlapping_hosts() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_normalized_host() => _result.FailureMessage.ShouldContain("bücher.example");
}
