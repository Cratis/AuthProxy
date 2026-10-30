// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_sticky_routing_is_enabled.given;

/// <summary>
/// A provider over a sticky "Reporting" service, with the change listener it registers captured, and a plain
/// "Portal" service next to it.
/// </summary>
public class a_provider_over_a_sticky_service : Specification
{
    protected MicroserviceReverseProxyConfigProvider _provider;
    protected C.AuthProxy _config;

    Action<C.AuthProxy, string?> _reload;

    protected static C.AuthProxy Configuration(
        bool sticky = true,
        string replicaHost = "reporting-headless.svc",
        bool accessToken = false) =>
        new()
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Reporting"] = new()
                {
                    Backend = new C.ServiceEndpoint
                    {
                        BaseUrl = "http://reporting:8080/",
                        StickyRouting = sticky ? new C.StickyRouting { Enabled = true, ReplicaHost = replicaHost } : null,
                    },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://reporting-ui:8080/" },
                    AccessToken = accessToken ? new C.ServiceAccessToken { Scopes = ["api://reporting"] } : null,
                },
                ["Portal"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://portal:8080/" },
                },
            },
        };

    protected static ClusterConfig BackendOf(IProxyConfig config, string service = "reporting") =>
        config.Clusters.Single(_ => _.ClusterId == $"{service}-backend-cluster");

    protected void Reload(C.AuthProxy next) => _reload(next, Options.DefaultName);

    protected void Provide(C.AuthProxy config)
    {
        _provider?.Dispose();
        _config = config;
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        monitor.OnChange(Arg.Do<Action<C.AuthProxy, string?>>(listener => _reload = listener));
        _provider = new(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }

    void Establish() => Provide(Configuration());

    void Destroy() => _provider.Dispose();
}
