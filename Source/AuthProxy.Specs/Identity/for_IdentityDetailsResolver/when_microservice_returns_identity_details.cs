// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

public class when_microservice_returns_identity_details : Specification
{
    IdentityDetailsResolver _resolver;
    DefaultHttpContext _context;
    IdentityProviderResult _result;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend/" } }
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, /*lang=json,strict*/ "{\"displayName\":\"John Doe\"}")));
        var inviteTokenValidator = Substitute.For<IInviteTokenValidator>();

        _resolver = new IdentityDetailsResolver(optionsMonitor, httpClientFactory, inviteTokenValidator, Substitute.For<ILogger<IdentityDetailsResolver>>());
        _context = new DefaultHttpContext();
    }

    async Task Because() => _result = await _resolver.Resolve(_context, new ClientPrincipal { UserId = "user-1" }, Guid.NewGuid().ToString());

    [Fact] void should_be_authorized() => Assert.True(_result.IsAuthorized);
    [Fact] void should_write_identity_cookie_to_response() => Assert.NotEmpty(_context.Response.Headers.SetCookie.ToString());
}
