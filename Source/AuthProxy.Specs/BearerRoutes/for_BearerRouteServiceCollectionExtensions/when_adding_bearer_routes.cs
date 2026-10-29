// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteServiceCollectionExtensions;

public class when_adding_bearer_routes : Specification
{
    ServiceProvider _services;
    HttpClient _client;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddBearerRoutes();
        _services = builder.Services.BuildServiceProvider();
        _client = _services.GetRequiredService<IHttpClientFactory>().CreateClient(BearerRouteDefaults.MetadataHttpClientName);
    }
    void Destroy()
    {
        _client.Dispose();
        _services.Dispose();
    }
    [Fact] void should_limit_the_timeout() => _client.Timeout.ShouldEqual(BearerRouteServiceCollectionExtensions.MetadataTimeout);
    [Fact] void should_limit_the_response_buffer() => _client.MaxResponseContentBufferSize.ShouldEqual(BearerRouteServiceCollectionExtensions.MaximumMetadataSize);
}
