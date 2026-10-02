// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_selecting_a_tenant_with_no_forwardable_identity : given.an_invalid_canonical_session
{
    void Establish()
    {
        _context.Request.Path = WellKnownPaths.SelectTenant;
        _context.Request.QueryString = new QueryString("?tenantId=tenant-a");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_sign_out_the_invalid_session() => _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties?>());
    [Fact] void should_clear_the_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenant}=;");
    [Fact] void should_redirect_to_provider_selection() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_include_the_invalid_session_reason_and_destination() => _context.Response.Headers.Location.ToString().ShouldEqual($"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.InvalidSession}&returnUrl={Uri.EscapeDataString(WellKnownPaths.SelectTenant + "?tenantId=tenant-a")}");
    [Fact] void should_not_call_the_tenant_endpoint() => _endpointCalls.ShouldEqual(0);
    [Fact] void should_not_serve_an_error_page() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
