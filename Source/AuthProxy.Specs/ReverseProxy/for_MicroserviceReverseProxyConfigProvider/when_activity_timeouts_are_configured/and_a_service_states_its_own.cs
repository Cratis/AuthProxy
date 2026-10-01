// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_activity_timeouts_are_configured;

public class and_a_service_states_its_own : given.a_provider_over_a_configuration
{
    void Establish()
    {
        _configuration.ActivityTimeout = TimeSpan.FromMinutes(30);
        _configuration.Services = new Dictionary<string, C.Service>
        {
            ["Streams"] = new()
            {
                ActivityTimeout = TimeSpan.FromHours(2),
                Backend = new C.ServiceEndpoint { BaseUrl = "https://streams.local/" },
                Frontend = new C.ServiceEndpoint { BaseUrl = "https://streams-web.local/" },
            },
            ["Other"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://other.local/" },
            },
        };
    }

    void Because() => CreateProvider();

    [Fact] void should_apply_it_to_the_backend_of_that_service() => ActivityTimeoutOf("streams-backend-cluster").ShouldEqual(TimeSpan.FromHours(2));
    [Fact] void should_apply_it_to_the_frontend_of_that_service() => ActivityTimeoutOf("streams-frontend-cluster").ShouldEqual(TimeSpan.FromHours(2));
    [Fact] void should_leave_other_services_on_the_root_value() => ActivityTimeoutOf("other-backend-cluster").ShouldEqual(TimeSpan.FromMinutes(30));
}
