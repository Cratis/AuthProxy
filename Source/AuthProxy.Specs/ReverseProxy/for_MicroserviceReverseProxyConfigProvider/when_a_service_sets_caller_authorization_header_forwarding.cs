// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_a_service_sets_caller_authorization_header_forwarding : Specification
{
    Yarp.ReverseProxy.Configuration.IProxyConfig _config;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Forwarding"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" },
                    CallerAuthorizationHeader = C.CallerAuthorizationHeaderForwarding.Forward
                },
                ["Plain"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://plain.local/" }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);
        _config = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>()).GetConfig();
    }

    string? Setting(string cluster) =>
        _config.Clusters.Single(_ => _.ClusterId == cluster).Metadata!.GetValueOrDefault(MicroserviceReverseProxyConfigProvider.CallerAuthorizationHeaderMetadataKey);

    [Fact] void should_record_the_setting_on_the_backend_cluster() => Setting("forwarding-backend-cluster").ShouldEqual("Forward");
    [Fact] void should_record_the_setting_on_the_frontend_cluster() => Setting("forwarding-frontend-cluster").ShouldEqual("Forward");
    [Fact] void should_record_nothing_for_the_default() => Setting("plain-backend-cluster").ShouldBeNull();
}
