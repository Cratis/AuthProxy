// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_a_host_entry_is_a_wildcard : given.a_service_routing_validator
{
    void Establish() => _services["one"] = Routable("*.example.com");

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
}
