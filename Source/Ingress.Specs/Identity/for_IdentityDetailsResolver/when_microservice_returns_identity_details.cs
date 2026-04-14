// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.Ingress.Identity.for_IdentityDetailsResolver;

public class when_microservice_returns_identity_details : Specification
{
    IdentityDetailsResolver _resolver;
    DefaultHttpContext _context;
    IdentityProviderResult _result;

    void Establish()
    {
        var config = new IngressConfig
        {
            Microservices = new Dictionary<string, MicroserviceConfig>
            {
                ["main"] = new() { Backend = new MicroserviceEndpointConfig { BaseUrl = "http://backend/" } }
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, /*lang=json,strict*/ "{\"displayName\":\"John Doe\"}")));

        _resolver = new IdentityDetailsResolver(optionsMonitor, httpClientFactory, Substitute.For<ILogger<IdentityDetailsResolver>>());
        _context = new DefaultHttpContext();
    }

    async Task Because() => _result = await _resolver.Resolve(_context, new ClientPrincipal { UserId = "user-1" }, Guid.NewGuid());

    [Fact] void should_be_authorized() => Assert.True(_result.IsAuthorized);
    [Fact] void should_write_identity_cookie_to_response() => Assert.NotEmpty(_context.Response.Headers.SetCookie.ToString());
}
