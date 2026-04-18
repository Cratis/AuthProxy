// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_IdentityServiceCollectionExtensions;

public class when_adding_identity_resolution : Specification
{
    IServiceCollection _services;
    ServiceProvider _serviceProvider;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddIdentityResolution();
        _services = builder.Services;
        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    [Fact]
    void should_register_identity_details_resolver() =>
        _services.Any(_ =>
            _.ServiceType == typeof(IIdentityDetailsResolver)
            && _.ImplementationType == typeof(IdentityDetailsResolver)
            && _.Lifetime == ServiceLifetime.Singleton).ShouldBeTrue();

    [Fact] void should_register_http_client_factory() =>
        _serviceProvider.GetRequiredService<IHttpClientFactory>().ShouldNotBeNull();
}
