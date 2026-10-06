// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutingConfigurationValidator;

public class when_a_host_entry_is_an_ascii_name_with_double_and_trailing_hyphens : given.a_service_routing_validator
{
    void Establish()
    {
        _services["cluster"] = Routable("my--svc.default.svc.cluster.local:8080");
        _services["database"] = Routable("db--primary:5432");
        _services["edge"] = Routable("a-.example");
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
