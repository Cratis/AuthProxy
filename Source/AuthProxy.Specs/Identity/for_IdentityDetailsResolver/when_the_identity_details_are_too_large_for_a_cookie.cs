// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

public class when_the_identity_details_are_too_large_for_a_cookie : Specification
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
                ["main"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://backend/" },
                    IdentityVerification = C.IdentityVerificationMode.BestEffort
                }
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        // A few hundred grants, as a long-lived maintainer accumulates: well past what a cookie or an ingress buffer carries.
        var grants = string.Join(',', Enumerable.Range(0, 400).Select(_ => $"{{\"projectId\":\"{Guid.NewGuid()}\",\"role\":1}}"));
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, "{\"projectAccess\":[" + grants + "]}")));

        _resolver = new IdentityDetailsResolver(optionsMonitor, httpClientFactory, [], Substitute.For<IMemoryCache>(), Substitute.For<IIdentityAuthorizationCache>(), Substitute.For<ILogger<IdentityDetailsResolver>>());
        _context = new DefaultHttpContext();
    }

    async Task Because() => _result = await _resolver.Resolve(_context, new ClientPrincipal { UserId = "user-1" }, Guid.NewGuid().ToString());

    [Fact] void should_still_be_authorized() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_not_write_an_identity_cookie_value() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain("projectId");
    [Fact] void should_keep_the_set_cookie_headers_small() => _context.Response.Headers.SetCookie.ToString().Length.ShouldBeLessThan(1024);
    [Fact] void should_expire_any_stale_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain("expires=");
}
