// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_RemoteAuthenticationFailureHandler;

public class when_remote_sign_in_fails_with_a_return_url : given.a_remote_authentication_failure_context
{
    RemoteFailureContext _failureContext;

    void Establish()
    {
        // Stale handshake cookies from earlier attempts — one at the root path and, from an older AuthProxy
        // version, one scoped to the callback path — alongside an unrelated cookie that must be preserved.
        _context.Request.Headers.Cookie =
            $"{Cookies.CorrelationPrefix}abc=one; {Cookies.NoncePrefix}def=two; keep-me=value";

        _failureContext = new RemoteFailureContext(_context, _scheme, _options, new InvalidOperationException("Correlation failed."))
        {
            Properties = new AuthenticationProperties { RedirectUri = "/deep/link" }
        };
    }

    async Task Because() => await RemoteAuthenticationFailureHandler.HandleRemoteFailure(_failureContext);

    [Fact] void should_handle_the_response() => _failureContext.Result.Handled.ShouldBeTrue();
    [Fact] void should_redirect() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);

    [Fact] void should_redirect_to_provider_selection_with_the_reason_and_return_url() =>
        _context.Response.Headers.Location.ToString().ShouldEqual(
            $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.RemoteFailure}&returnUrl={Uri.EscapeDataString("/deep/link")}");

    [Fact] void should_clear_the_correlation_cookie_at_the_root_path() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.CorrelationPrefix}abc=; expires");

    [Fact] void should_clear_the_correlation_cookie_at_the_callback_path() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain("path=/signin-microsoft");

    [Fact] void should_clear_the_nonce_cookie() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.NoncePrefix}def=; expires");

    [Fact] void should_not_clear_unrelated_cookies() =>
        _context.Response.Headers.SetCookie.ToString().ShouldNotContain("keep-me=;");
}
