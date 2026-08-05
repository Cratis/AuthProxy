// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_the_configuration_reloads;

/// <summary>
/// Routes are not the only half of the table a reload can change. A service that moves to a new address is
/// the same kind of drift as a withdrawn anonymous path — the configuration says one thing and the proxy
/// goes on forwarding to the old destination — so the clusters are rebuilt with the routes.
/// </summary>
public class and_a_service_endpoint_changed : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;
    Action<C.AuthProxy, string?> _reload;
    IReadOnlyList<ClusterConfig> _clusters;

    static C.AuthProxy ConfigurationServing(string baseUrl) =>
        new()
        {
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new() { Frontend = new C.ServiceEndpoint { BaseUrl = baseUrl } },
            },
        };

    void Establish()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(ConfigurationServing("https://frontend.local/"));
        monitor.OnChange(Arg.Do<Action<C.AuthProxy, string?>>(listener => _reload = listener));

        _provider = new MicroserviceReverseProxyConfigProvider(
            monitor,
            Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }

    void Because()
    {
        _reload(ConfigurationServing("https://moved.local/"), Options.DefaultName);
        _clusters = _provider.GetConfig().Clusters;
    }

    [Fact] void should_forward_to_the_destination_the_replacement_declares() =>
        _clusters.Single(_ => _.ClusterId == "app-frontend-cluster").Destinations!.Values.Single().Address.ShouldEqual("https://moved.local/");
}
