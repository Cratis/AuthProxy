// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_ReverseProxyExtensions;

public class when_setting_up_reverse_proxy : Specification
{
    ServiceProvider _serviceProvider;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:Catalog:Backend:BaseUrl"] = "https://catalog-backend.local/"
        });

        builder.SetupReverseProxy();

        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    [Fact] void should_register_microservice_proxy_config_provider() =>
        _serviceProvider.GetRequiredService<MicroserviceReverseProxyConfigProvider>().ShouldNotBeNull();

    [Fact] void should_register_i_proxy_config_provider() =>
        _serviceProvider.GetRequiredService<IProxyConfigProvider>().ShouldBeOfExactType<MicroserviceReverseProxyConfigProvider>();
}
