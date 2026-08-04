// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_the_caller_is_not_navigating;

/// <summary>
/// A caller that is not navigating to a document must be refused with <c>401</c>, not handed the
/// provider-selection page at <c>200</c>.
/// <para>
/// The status code is the defect, not the page. A webhook, an e-sign callback or any integration reads
/// <c>200</c> as delivered and never retries; nothing errors, nothing is queued for redelivery. The same
/// <c>200</c> defeats the conventional <c>!response.ok</c> check in every browser client — Arc's own
/// identity bootstrap calls <c>/.cratis/me</c> and gets HTML with <c>response.ok</c> true, so only the
/// subsequent <c>.json()</c> fails.
/// </para>
/// <para>
/// The providers cookie is withheld with the page: it exists so the selection page can render the
/// choices, and there is no page here.
/// </para>
/// <para>
/// No authority and no service minting tokens are configured here, so there is no credential to name and
/// the refusal carries no challenge — sending one would point the caller at something nothing would
/// accept. The cases where a challenge <em>is</em> real are
/// <see cref="and_a_bearer_token_is_accepted"/> and <see cref="and_a_service_mints_its_own_tokens"/>.
/// </para>
/// </summary>
public class and_multiple_providers_are_configured : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPageProvider;
    bool _nextCalled;

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

        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _errorPageProvider
            .WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>())
            .Returns(Task.CompletedTask);

        _middleware = new SelectProviderMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            proxyConfig,
            authConfig,
            _errorPageProvider,
            Substitute.For<ITenantResolver>(),
            Substitute.For<IAuthenticationSchemeProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/api/orders";
        _context.Request.Headers["Sec-Fetch-Dest"] = "empty";
        _context.Request.Headers.Accept = "*/*";
        _context.Response.Body = new MemoryStream();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_not_name_a_challenge_that_cannot_work() => _context.Response.Headers.WWWAuthenticate.ToString().ShouldBeEmpty();
    [Fact] void should_not_serve_any_page() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
    [Fact] void should_not_set_the_providers_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.Providers);
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
