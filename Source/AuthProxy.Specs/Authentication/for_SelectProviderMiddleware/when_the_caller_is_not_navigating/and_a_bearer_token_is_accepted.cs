// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_the_caller_is_not_navigating;

/// <summary>
/// A refusal must name a credential the caller can come back with when one exists.
/// <para>
/// A <c>401</c> is required to carry a <c>WWW-Authenticate</c> challenge, and a bare one tells an
/// integration only that it was refused — not that presenting a bearer token would have worked. With JWT
/// bearer configured the token is obtainable from the authority, so the challenge is real and actionable.
/// </para>
/// </summary>
public class and_a_bearer_token_is_accepted : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy());

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider { Name = "Provider One", Authority = "https://a.example.com", ClientId = "c1" },
                new C.OidcProvider { Name = "Provider Two", Authority = "https://b.example.com", ClientId = "c2" }
            ]
        });

        var schemeProvider = Substitute.For<IAuthenticationSchemeProvider>();
        schemeProvider.GetSchemeAsync(JwtBearerDefaults.AuthenticationScheme)
            .Returns(new AuthenticationScheme(
                JwtBearerDefaults.AuthenticationScheme,
                JwtBearerDefaults.AuthenticationScheme,
                typeof(JwtBearerHandler)));

        _middleware = new SelectProviderMiddleware(
            _ => Task.CompletedTask,
            proxyConfig,
            authConfig,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ITenantResolver>(),
            schemeProvider);

        _context = new DefaultHttpContext();
        _context.Request.Path = "/api/orders";
        _context.Request.Headers["Sec-Fetch-Dest"] = "empty";
        _context.Response.Body = new MemoryStream();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_name_the_bearer_challenge() => _context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual("Bearer");
}
