// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Identity.for_IdentityForwardingGuardMiddleware;

public class when_an_authenticated_session_cannot_be_forwarded_for_a_non_navigation_caller : given.a_proxied_request
{
    void Establish()
    {
        SetAuthenticatedUser();
        _canonicalIdentityResolver
            .Resolve(Arg.Any<ClaimsPrincipal>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<bool>())
            .Returns(CanonicalIdentityResolution.Failed());

        // A fetch() issued by the application — a redirect to a page would read as success; a status is
        // the answer it can act on.
        _context.Request.Headers["Sec-Fetch-Dest"] = "empty";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_refuse_with_unauthorized() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);

    [Fact] void should_sign_the_caller_out_of_the_cookie_scheme() =>
        _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties?>());
}
