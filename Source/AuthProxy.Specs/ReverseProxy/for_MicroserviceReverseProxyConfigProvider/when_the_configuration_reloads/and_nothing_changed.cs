// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_the_configuration_reloads;

/// <summary>
/// A file-backed configuration source commonly raises two change notifications for a single edit, and the
/// second describes the configuration already being served.
/// <para>
/// A new <see cref="IProxyConfig"/> is how this provider tells YARP the table changed — YARP answers it by
/// tearing down and rebuilding its routes — so the configuration served is the same object when the rebuild
/// arrives at the same table. It is the same object here even though the reload supplies a separately
/// constructed configuration declaring the same prefix, which is what a second notification for one edit
/// actually looks like.
/// </para>
/// </summary>
public class and_nothing_changed : given.a_provider_over_a_reloadable_configuration
{
    IProxyConfig _before;
    IProxyConfig _after;

    void Because()
    {
        _before = _provider.GetConfig();
        _monitor.Reload(ConfigurationDeclaring("/portal"));
        _after = _provider.GetConfig();
    }

    [Fact] void should_go_on_serving_the_table_it_already_built() =>
        ReferenceEquals(_after, _before).ShouldBeTrue();

    [Fact] void should_still_route_the_declared_prefix() =>
        _after.Routes.Single(_ => _.Match.Path == "/portal/{**catch-all}").AuthorizationPolicy.ShouldEqual("anonymous");
}
