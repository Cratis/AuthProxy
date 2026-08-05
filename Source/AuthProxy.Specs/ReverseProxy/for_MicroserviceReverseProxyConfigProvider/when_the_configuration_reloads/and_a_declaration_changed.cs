// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_the_configuration_reloads;

/// <summary>
/// The route table is the fourth component that has to agree on what counts as an anonymous path, and the
/// only one not consulted per request — so it has to follow a reload rather than the process lifetime.
/// <para>
/// Withdrawal is the direction that matters. Three middlewares read the configuration on every request and
/// stop treating a withdrawn prefix as anonymous the moment it reloads, while a table built once at startup
/// would go on serving that prefix from a route carrying the relaxed authorization policy — the backstop
/// still open under a surface an operator believes they just closed. Asserted in both directions, so a
/// rebuild that simply dropped every anonymous route would not satisfy it.
/// </para>
/// </summary>
public class and_a_declaration_changed : given.a_provider_over_a_reloadable_configuration
{
    IReadOnlyList<RouteConfig> _routes;

    void Because()
    {
        _monitor.Reload(ConfigurationDeclaring("/status"));
        _routes = _provider.GetConfig().Routes;
    }

    [Fact] void should_route_the_prefix_the_replacement_declares() =>
        _routes.Single(_ => _.Match.Path == "/status/{**catch-all}").AuthorizationPolicy.ShouldEqual("anonymous");

    [Fact] void should_no_longer_route_the_withdrawn_prefix() =>
        _routes.Any(_ => _.Match.Path == "/portal/{**catch-all}").ShouldBeFalse();

    [Fact] void should_relax_the_policy_on_nothing_but_the_declared_prefix() =>
        _routes.Count(_ => _.AuthorizationPolicy == "anonymous").ShouldEqual(1);
}
