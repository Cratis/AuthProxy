// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_activity_timeouts_are_configured;

public class and_an_endpoint_states_its_own : given.a_provider_over_a_configuration
{
    void Establish()
    {
        _configuration.ActivityTimeout = TimeSpan.FromMinutes(30);
        _configuration.Services = new Dictionary<string, C.Service>
        {
            ["App"] = new()
            {
                ActivityTimeout = TimeSpan.FromHours(2),
                Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/", ActivityTimeout = TimeSpan.FromSeconds(45) },
                Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" },
            },
        };
    }

    void Because() => CreateProvider();

    [Fact] void should_apply_it_to_that_endpoint() => ActivityTimeoutOf("app-backend-cluster").ShouldEqual(TimeSpan.FromSeconds(45));
    [Fact] void should_leave_the_sibling_endpoint_on_the_service_value() => ActivityTimeoutOf("app-frontend-cluster").ShouldEqual(TimeSpan.FromHours(2));
}
