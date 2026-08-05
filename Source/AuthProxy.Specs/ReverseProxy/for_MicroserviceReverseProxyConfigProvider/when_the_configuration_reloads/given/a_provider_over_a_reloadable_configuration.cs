// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_the_configuration_reloads.given;

/// <summary>
/// A provider built over a configuration that can be replaced, declaring <c>/portal</c> anonymous to start
/// with. A single service with only a frontend keeps the generated table small enough to read.
/// </summary>
public class a_provider_over_a_reloadable_configuration : Specification
{
    protected MicroserviceReverseProxyConfigProvider _provider;
    protected ReloadableOptionsMonitor _monitor;

    protected static C.AuthProxy ConfigurationDeclaring(params string[] anonymousPaths) =>
        new()
        {
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new()
                {
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" },
                    AnonymousPaths = [.. anonymousPaths],
                },
            },
        };

    void Establish()
    {
        _monitor = new ReloadableOptionsMonitor(ConfigurationDeclaring("/portal"));
        _provider = new MicroserviceReverseProxyConfigProvider(
            _monitor,
            Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }
}
