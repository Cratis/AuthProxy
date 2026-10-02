// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_session_has_no_forwardable_identity_and_the_caller_is_not_navigating : given.an_invalid_canonical_session
{
    void Establish() => _context.Request.Headers.Remove("Sec-Fetch-Dest");

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_sign_out_the_invalid_session() => _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties?>());
    [Fact] void should_clear_the_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Identity}=;");
    [Fact] void should_respond_with_unauthorized() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_not_redirect() => _context.Response.Headers.Location.ToString().ShouldBeEmpty();
    [Fact] void should_not_write_a_response_body() => _context.Response.Body.Length.ShouldEqual(0);
    [Fact] void should_not_call_the_tenant_endpoint() => _endpointCalls.ShouldEqual(0);
    [Fact] void should_not_serve_an_error_page() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
