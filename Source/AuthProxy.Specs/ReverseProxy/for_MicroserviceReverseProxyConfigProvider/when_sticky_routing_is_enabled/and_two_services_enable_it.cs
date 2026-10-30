// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_sticky_routing_is_enabled;

public class and_two_services_enable_it : given.a_provider_over_a_sticky_service
{
    void Establish()
    {
        var config = Configuration();
        config.Services["Portal"].Backend.StickyRouting = new C.StickyRouting { Enabled = true };
        Provide(config);
    }

    [Fact]
    void should_name_a_cookie_per_service() =>
        new[] { "reporting", "portal" }
            .Select(service => BackendOf(_provider.GetConfig(), service).SessionAffinity.AffinityKeyName)
            .ShouldContainOnly(".cratis-affinity-reporting", ".cratis-affinity-portal");
}
