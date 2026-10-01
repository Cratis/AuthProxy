// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_activity_timeouts_are_configured.given;

/// <summary>
/// A provider built over a configuration a spec states, exposing the activity timeout each cluster ended up with.
/// </summary>
public class a_provider_over_a_configuration : Specification
{
    protected C.AuthProxy _configuration;
    protected MicroserviceReverseProxyConfigProvider _provider;

    protected TimeSpan? ActivityTimeoutOf(string clusterId) =>
        _provider.GetConfig().Clusters.Single(_ => _.ClusterId == clusterId).HttpRequest!.ActivityTimeout;

    void Establish()
    {
        _configuration = new();
    }

    protected void CreateProvider()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(_configuration);
        _provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }
}
