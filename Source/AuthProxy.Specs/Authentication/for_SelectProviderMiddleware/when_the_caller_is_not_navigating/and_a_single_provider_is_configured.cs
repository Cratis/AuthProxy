// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_the_caller_is_not_navigating;

/// <summary>
/// With a single provider the refusal is an OIDC challenge — a redirect to the provider's login page —
/// which is the same silent success in a different shape: a client that follows redirects ends up reading
/// the identity provider's login page as a <c>200</c>, so the rejection is again invisible.
/// <para>
/// A caller that is not navigating gets <c>401</c> instead, which is the answer it can actually act on.
/// The challenge is still the right response to a browser navigating to a protected page, and that is
/// covered by <see cref="when_single_provider_is_configured"/>.
/// </para>
/// </summary>
public class and_a_single_provider_is_configured : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;
    bool _challenged;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy());

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "my-provider", Authority = "https://auth.example.com", ClientId = "id" }]
        });

        _middleware = new SelectProviderMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            proxyConfig,
            authConfig,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ITenantResolver>(),
            Substitute.For<IAuthenticationSchemeProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/api/orders";
        _context.Request.Headers["Sec-Fetch-Dest"] = "empty";
        _context.Response.Body = new MemoryStream();

        var authService = Substitute.For<IAuthenticationService>();
        authService
            .ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<AuthenticationProperties>())
            .Returns(_ =>
            {
                _challenged = true;
                return Task.CompletedTask;
            });

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(authService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_not_redirect_to_the_provider() => _challenged.ShouldBeFalse();
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
