// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_a_host_entry_cannot_be_parsed_by_endpoint_routing : given.a_service_routing_validator
{
    [Theory]
    [InlineData("example.com:abc")]
    [InlineData("example.com:")]
    [InlineData("[::1]")]
    [InlineData("[::1]:8443")]
    [InlineData("::1")]
    [InlineData("xn--a.example")]
    [InlineData("xn--.example")]
    public void should_refuse_the_configuration_at_startup(string host)
    {
        _services["one"] = Routable(host);

        Validate();

        _result.Failed.ShouldBeTrue();
    }
}
