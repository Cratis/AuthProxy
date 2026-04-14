// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;
using Cratis.Ingress.Invites;

namespace Cratis.Ingress.Identity.for_IdentityDetailsResolver;

public class when_identity_cookie_is_present_and_invite_cookie_exists : Specification
{
    IdentityDetailsResolver _resolver;
    DefaultHttpContext _context;
    IHttpClientFactory _httpClientFactory;
    IdentityProviderResult _result;

    void Establish()
    {
        var config = new IngressConfig
        {
            Microservices = new Dictionary<string, MicroserviceConfig>
            {
                ["main"] = new() { Backend = new MicroserviceEndpointConfig { BaseUrl = "http://backend" } }
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        _httpClientFactory = Substitute.For<IHttpClientFactory>();
        _httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, /*lang=json,strict*/ "{\"displayName\":\"John Doe\"}")));

        var inviteTokenValidator = Substitute.For<IInviteTokenValidator>();
        inviteTokenValidator.TryGetClaim("invite-token", "jti", out Arg.Any<string>())
            .Returns(callInfo =>
            {
                callInfo[2] = "7cf1cec4-3fdf-4dc1-9b0c-04d42d928f6e";
                return true;
            });

        _resolver = new IdentityDetailsResolver(optionsMonitor, _httpClientFactory, inviteTokenValidator, Substitute.For<ILogger<IdentityDetailsResolver>>());

        _context = new DefaultHttpContext();
        _context.Request.Headers.Cookie = $"{Cookies.Identity}=existing-value; {Cookies.InviteToken}=invite-token";
    }

    async Task Because() => _result = await _resolver.Resolve(_context, new ClientPrincipal { UserId = "user-1" }, Guid.NewGuid());

    [Fact] void should_be_authorized() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_call_the_http_client_to_refresh_details() => _httpClientFactory.Received(1).CreateClient(Arg.Any<string>());
}
