// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_sticky_routing_is_enabled;

public class and_the_configuration_reloads_unchanged : given.a_provider_over_a_sticky_service
{
    IProxyConfig _before;
    IProxyConfig _after;

    void Because()
    {
        _before = _provider.GetConfig();
        Reload(Configuration());
        _after = _provider.GetConfig();
    }

    [Fact] void should_go_on_serving_the_table_it_already_built() => ReferenceEquals(_after, _before).ShouldBeTrue();
}
