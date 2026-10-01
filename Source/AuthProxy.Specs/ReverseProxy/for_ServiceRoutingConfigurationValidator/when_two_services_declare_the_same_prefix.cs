// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_two_services_declare_the_same_prefix : given.a_service_routing_validator
{
    void Establish()
    {
        _services["one"] = Routable();
        _services["one"].PathPrefix = "/reports";
        _services["two"] = Routable();
        _services["two"].PathPrefix = "/Reports";
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_both_services() => _result.FailureMessage.ShouldContain("'one' and 'two'");
}
