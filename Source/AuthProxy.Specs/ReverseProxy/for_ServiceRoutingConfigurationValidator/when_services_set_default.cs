// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_services_set_default : given.a_service_routing_validator
{
    ValidateOptionsResult _two;
    ValidateOptionsResult _withPrefix;
    ValidateOptionsResult _one;

    void Because()
    {
        _services["a"] = new() { Default = true, Backend = new C.ServiceEndpoint { BaseUrl = "http://a/" } };
        _services["b"] = new() { Default = true, Backend = new C.ServiceEndpoint { BaseUrl = "http://b/" } };
        Validate();
        _two = _result;

        _services.Clear();
        _services["a"] = new() { Default = true, PathPrefix = "/a", Backend = new C.ServiceEndpoint { BaseUrl = "http://a/" } };
        Validate();
        _withPrefix = _result;

        _services.Clear();
        _services["a"] = new() { Default = true, Backend = new C.ServiceEndpoint { BaseUrl = "http://a/" } };
        _services["b"] = new() { PathPrefix = "/b", Backend = new C.ServiceEndpoint { BaseUrl = "http://b/" } };
        Validate();
        _one = _result;
    }

    [Fact] void should_refuse_two_defaults() => _two.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_default_with_a_prefix() => _withPrefix.Failed.ShouldBeTrue();
    [Fact] void should_accept_one_default_beside_a_prefixed_service() => _one.Succeeded.ShouldBeTrue();
}
