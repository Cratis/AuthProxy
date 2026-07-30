// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

public class when_identity_revalidation_is_disabled : Specification
{
    IdentityDetailsResolver _resolver;
    DefaultHttpContext _context;
    IdentityProviderResult _result;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Session = new C.Session { IdentityRevalidationInterval = TimeSpan.Zero },
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

        _resolver = new IdentityDetailsResolver(optionsMonitor, httpClientFactory, [], Substitute.For<IMemoryCache>(), Substitute.For<ILogger<IdentityDetailsResolver>>());
        _context = new DefaultHttpContext();
    }

    async Task Because() => _result = await _resolver.Resolve(_context, new ClientPrincipal { UserId = "user-1" }, Guid.NewGuid().ToString());

    [Fact] void should_write_identity_cookie_to_response() => Assert.NotEmpty(_context.Response.Headers.SetCookie.ToString());
    [Fact] void should_write_the_identity_cookie_as_a_session_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain("max-age");
}
