// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

public class when_identity_cookie_is_already_present : Specification
{
    IdentityDetailsResolver _resolver;
    DefaultHttpContext _context;
    IHttpClientFactory _httpClientFactory;
    IdentityProviderResult _result;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend" } }
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _httpClientFactory = Substitute.For<IHttpClientFactory>();
        var inviteTokenValidator = Substitute.For<IInviteTokenValidator>();

        _resolver = new IdentityDetailsResolver(optionsMonitor, _httpClientFactory, inviteTokenValidator, Substitute.For<ILogger<IdentityDetailsResolver>>());

        _context = new DefaultHttpContext();
        _context.Request.Headers.Cookie = $"{Cookies.Identity}=existing-value";
    }

    async Task Because() => _result = await _resolver.Resolve(_context, new ClientPrincipal { UserId = "user-1" }, Guid.NewGuid());

    [Fact] void should_be_authorized() => Assert.True(_result.IsAuthorized);
    [Fact] void should_not_call_the_http_client() => _httpClientFactory.DidNotReceive().CreateClient(Arg.Any<string>());
}
