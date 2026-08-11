// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a completed sign-in sweeps the deployment-configured additional cookies alongside the
/// transient handshake cookies, so a stale foreign session cookie does not survive a fresh sign-in.
/// </summary>
public class when_a_configured_callback_sweeps_additional_cookies : configured_canonical_provider_callbacks
{
    DefaultHttpContext _httpContext;

    void Establish()
    {
        _rootConfiguration.Logout.AdditionalCookies.Add(new C.LogoutCookie { Name = "_oauth2_proxy_admin", Domain = ".cratis.studio" });

        _httpContext = Context();
        _httpContext.Request.Scheme = "https";
        _httpContext.Request.Host = new HostString("app.cratis.studio");
    }

    async Task Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("id", "github-subject")], "github"));
        var ticketContext = TicketContext(_httpContext, "github", _oauthOptions, principal, new AuthenticationProperties());
        await _oauthOptions.Events.OnTicketReceived(ticketContext);
    }

    [Fact]
    void should_delete_the_additional_cookie_for_the_request_host_and_for_its_domain() =>
        _httpContext.Response.Headers.SetCookie
            .Count(_ => _?.StartsWith("_oauth2_proxy_admin=;", StringComparison.Ordinal) == true)
            .ShouldEqual(2);

    [Fact]
    void should_scope_one_of_the_deletions_to_the_configured_domain() =>
        _httpContext.Response.Headers.SetCookie.ToString().ShouldContain("domain=.cratis.studio");
}
