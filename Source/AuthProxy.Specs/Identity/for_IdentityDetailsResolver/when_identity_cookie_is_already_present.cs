// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

/// <summary>
/// The readable <c>.cratis-identity</c> cookie must not, on its own, decide that a caller is authorized.
/// <para>
/// It is written non-HTTP-only so a frontend can render the signed-in user from it, which means script on
/// any proxied origin can write it — and a non-browser caller can simply send it. This resolver used to
/// short-circuit on its mere presence, without ever reading its value, so
/// <c>Cookie: .cratis-identity=x</c> alongside a valid session was enough to skip every configured
/// service's <c>/.cratis/me</c> authorization call, for as long as the caller kept sending it. A user
/// whose backend authorization had been revoked stayed authorized at the proxy by choice.
/// </para>
/// <para>
/// The services are called instead. What is allowed to skip them is the sealed record checked through
/// <see cref="IIdentityAuthorizationCache"/>, which is covered by its own specs.
/// </para>
/// </summary>
public class when_identity_cookie_is_already_present : Specification
{
    IdentityDetailsResolver _resolver;
    DefaultHttpContext _context;
    IHttpClientFactory _httpClientFactory;
    IIdentityAuthorizationCache _authorizationCache;
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
        _httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK, /*lang=json,strict*/ "{\"displayName\":\"John Doe\"}")));

        // No sealed record — which is exactly the position an attacker sending only the readable cookie
        // is in, because they cannot produce one.
        _authorizationCache = Substitute.For<IIdentityAuthorizationCache>();
        _authorizationCache.IsAuthorized(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>()).Returns(false);

        _resolver = new IdentityDetailsResolver(optionsMonitor, _httpClientFactory, [], Substitute.For<IMemoryCache>(), _authorizationCache, Substitute.For<ILogger<IdentityDetailsResolver>>());

        _context = new DefaultHttpContext();
        _context.Request.Headers.Cookie = $"{Cookies.Identity}=forged-value";
    }

    async Task Because() => _result = await _resolver.Resolve(_context, new ClientPrincipal { UserId = "user-1" }, Guid.NewGuid().ToString());

    [Fact] void should_still_call_the_identity_endpoint() => _httpClientFactory.Received().CreateClient(Arg.Any<string>());
    [Fact] void should_authorize_on_what_the_service_answered() => Assert.True(_result.IsAuthorized);
    [Fact] void should_record_the_authorization_it_resolved() =>
        _authorizationCache.Received(1).Record(_context, Arg.Any<ClientPrincipal>(), Arg.Any<string>());
}
