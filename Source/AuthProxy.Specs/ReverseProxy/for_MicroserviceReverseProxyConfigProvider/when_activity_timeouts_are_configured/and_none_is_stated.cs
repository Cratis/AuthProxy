// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_activity_timeouts_are_configured;

public class and_none_is_stated : given.a_provider_over_a_configuration
{
    void Establish() =>
        _configuration.Services = new Dictionary<string, C.Service>
        {
            ["App"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/" },
                Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" },
            },
        };

    void Because() => CreateProvider();

    [Fact] void should_keep_five_minutes_for_the_backend() => ActivityTimeoutOf("app-backend-cluster").ShouldEqual(TimeSpan.FromMinutes(5));
    [Fact] void should_keep_five_minutes_for_the_frontend() => ActivityTimeoutOf("app-frontend-cluster").ShouldEqual(TimeSpan.FromMinutes(5));
}
