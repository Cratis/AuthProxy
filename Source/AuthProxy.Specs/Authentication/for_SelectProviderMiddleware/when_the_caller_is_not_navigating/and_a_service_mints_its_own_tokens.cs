// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_the_caller_is_not_navigating;

/// <summary>
/// The bearer challenge is equally real when the token comes from AuthProxy itself.
/// <para>
/// A service configured for back-channel client credentials can exchange them at <c>/.cratis/token</c> for
/// a token this proxy accepts, so naming <c>Bearer</c> points the caller at a door that opens — with no
/// external authority configured at all.
/// </para>
/// </summary>
public class and_a_service_mints_its_own_tokens : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["test"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                    ClientCredentials = new C.ServiceClientCredentials { RoutePrefix = "/api" },
                },
            },
        });

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider { Name = "Provider One", Authority = "https://a.example.com", ClientId = "c1" },
                new C.OidcProvider { Name = "Provider Two", Authority = "https://b.example.com", ClientId = "c2" }
            ]
        });

        _middleware = new SelectProviderMiddleware(
            _ => Task.CompletedTask,
            proxyConfig,
            authConfig,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ITenantResolver>(),
            Substitute.For<IAuthenticationSchemeProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/api/orders";
        _context.Request.Headers["Sec-Fetch-Dest"] = "empty";
        _context.Response.Body = new MemoryStream();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_name_the_bearer_challenge() => _context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual("Bearer");
}
