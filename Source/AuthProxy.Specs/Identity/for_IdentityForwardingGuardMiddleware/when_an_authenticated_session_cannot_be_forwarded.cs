// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Identity.for_IdentityForwardingGuardMiddleware;

public class when_an_authenticated_session_cannot_be_forwarded : given.a_proxied_request
{
    void Establish()
    {
        SetAuthenticatedUser();
        _canonicalIdentityResolver
            .Resolve(Arg.Any<ClaimsPrincipal>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<bool>())
            .Returns(CanonicalIdentityResolution.Failed());

        // A browser navigating to a document — the caller a redirect to provider selection is an answer to.
        _context.Request.Path = "/dashboard";
        _context.Request.QueryString = new QueryString("?tab=activity");
        _context.Request.Headers["Sec-Fetch-Dest"] = "document";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();

    [Fact] void should_sign_the_caller_out_of_the_cookie_scheme() =>
        _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties?>());

    [Fact] void should_delete_the_identity_cookie() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Identity}=;");

    [Fact] void should_delete_the_identity_authorization_cookie() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.IdentityAuthorization}=;");

    [Fact] void should_redirect_to_provider_selection_with_the_reason_and_destination() =>
        _context.Response.Headers.Location.ToString().ShouldEqual(
            $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.InvalidSession}&returnUrl={Uri.EscapeDataString("/dashboard?tab=activity")}");
}
