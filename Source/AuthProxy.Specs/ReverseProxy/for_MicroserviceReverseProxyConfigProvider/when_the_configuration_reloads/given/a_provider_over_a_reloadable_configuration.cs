// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_the_configuration_reloads.given;

/// <summary>
/// A provider over a configuration declaring <c>/portal</c> anonymous, with the change listener it registers
/// captured so a spec can call it the way a reload does. A single service with only a frontend keeps the
/// generated table small enough to read.
/// </summary>
public class a_provider_over_a_reloadable_configuration : Specification
{
    protected MicroserviceReverseProxyConfigProvider _provider;

    Action<C.AuthProxy, string?> _reload;

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

    protected void Reload(C.AuthProxy next) => _reload(next, Options.DefaultName);

    void Establish()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(ConfigurationDeclaring("/portal"));
        monitor.OnChange(Arg.Do<Action<C.AuthProxy, string?>>(listener => _reload = listener));

        _provider = new MicroserviceReverseProxyConfigProvider(
            monitor,
            Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }
}
