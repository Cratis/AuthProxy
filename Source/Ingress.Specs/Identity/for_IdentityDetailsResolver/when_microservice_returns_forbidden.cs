// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.Ingress.Identity.for_IdentityDetailsResolver;

public class when_microservice_returns_forbidden : Specification
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
            new System.Net.Http.HttpClient(new FakeHttpMessageHandler(HttpStatusCode.Forbidden)));

        _resolver = new IdentityDetailsResolver(optionsMonitor, httpClientFactory, Substitute.For<ILogger<IdentityDetailsResolver>>());
        _context = new DefaultHttpContext();
    }

    async Task Because() => _result = await _resolver.Resolve(_context, new ClientPrincipal { UserId = "user-1" }, Guid.NewGuid());

    [Fact] void should_not_be_authorized() => Assert.False(_result.IsAuthorized);
    [Fact] void should_set_403_on_response() => Assert.Equal(StatusCodes.Status403Forbidden, _context.Response.StatusCode);
}
