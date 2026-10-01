// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_a_token_forwarding_binding_changes : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;
    Action<C.AuthProxy, string?> _reload;
    C.AuthProxy _config;
    IProxyConfig _original;
    IProxyConfig _newPolicy;
    IProxyConfig _newAddress;

    void Establish()
    {
        _config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Reporting"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://old-backend/" },
                    AccessToken = new C.ServiceAccessToken { Scopes = ["old-audience"], Resource = "old-resource", Provider = "old-provider" },
                },
            },
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(_config);
        monitor.OnChange(Arg.Do<Action<C.AuthProxy, string?>>(listener => _reload = listener));
        _provider = new(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
        _original = _provider.GetConfig();
    }

    void Because()
    {
        _config.Services["Reporting"].AccessToken!.Scopes[0] = "new-audience";
        _reload(_config, Options.DefaultName);
        _newPolicy = _provider.GetConfig();
        _config.Services["Reporting"].Backend!.BaseUrl = "https://new-backend/";
        _reload(_config, Options.DefaultName);
        _newAddress = _provider.GetConfig();
    }

    void Destroy() => _provider.Dispose();

    C.ServiceAccessToken OriginalPolicy() => JsonSerializer.Deserialize<C.ServiceAccessToken>(_original.Clusters.Single().Metadata![MicroserviceReverseProxyConfigProvider.AccessTokenMetadataKey])!;

    [Fact] void should_version_the_cluster_when_only_the_policy_changes() => (_original.Clusters.Single().ClusterId != _newPolicy.Clusters.Single().ClusterId).ShouldBeTrue();
    [Fact] void should_version_the_cluster_when_only_the_address_changes() => (_newPolicy.Clusters.Single().ClusterId != _newAddress.Clusters.Single().ClusterId).ShouldBeTrue();
    [Fact] void should_version_the_destination_when_the_binding_changes() => (_original.Clusters.Single().Destinations!.Single().Key != _newAddress.Clusters.Single().Destinations!.Single().Key).ShouldBeTrue();
    [Fact] void should_keep_the_original_scopes_immutable() => OriginalPolicy().Scopes.ShouldContainOnly("old-audience");
    [Fact] void should_keep_the_original_resource() => OriginalPolicy().Resource.ShouldEqual("old-resource");
    [Fact] void should_keep_the_original_provider() => OriginalPolicy().Provider.ShouldEqual("old-provider");
    [Fact] void should_bind_all_routes_to_the_selected_cluster() => _newAddress.Routes.All(_ => _.ClusterId == _newAddress.Clusters.Single().ClusterId).ShouldBeTrue();
}
