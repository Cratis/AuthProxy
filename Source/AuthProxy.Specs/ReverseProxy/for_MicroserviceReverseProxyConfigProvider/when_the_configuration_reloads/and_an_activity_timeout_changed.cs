// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_the_configuration_reloads;

/// <summary>
/// The timeout lives on the cluster, so a reload that only changes it has to reach the table being served —
/// otherwise an operator who lengthens it to stop a stream being cut would see no effect until a restart.
/// </summary>
public class and_an_activity_timeout_changed : given.a_provider_over_a_reloadable_configuration
{
    void Because()
    {
        var next = ConfigurationDeclaring("/portal");
        next.ActivityTimeout = TimeSpan.FromMinutes(20);
        Reload(next);
    }

    [Fact] void should_serve_the_replacement_timeout() =>
        _provider.GetConfig().Clusters.Single(_ => _.ClusterId == "app-frontend-cluster").HttpRequest!.ActivityTimeout.ShouldEqual(TimeSpan.FromMinutes(20));
}
