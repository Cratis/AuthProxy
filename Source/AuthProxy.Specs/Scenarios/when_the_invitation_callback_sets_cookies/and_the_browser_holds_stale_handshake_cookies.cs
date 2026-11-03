// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

namespace Cratis.AuthProxy.Scenarios.when_the_invitation_callback_sets_cookies;

/// <summary>A browser holding handshake cookies from six abandoned sign-in attempts.</summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_browser_holds_stale_handshake_cookies(CallbackCookiesAuthProxyFactory factory) : IClassFixture<CallbackCookiesAuthProxyFactory>, IAsyncLifetime
{
    readonly CallbackCookieScenario _scenario = new();

    public async ValueTask InitializeAsync() => await _scenario.Run(factory, nameof(and_the_browser_holds_stale_handshake_cookies), 6, false);

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] void should_redirect_to_the_lobby() => Assert.StartsWith(OidcCallbackAuthProxyFactory.LobbyUrl, _scenario.SignIn.Callback.Headers.Location?.ToString());
    [Fact] void should_establish_the_session_in_one_unchunked_cookie() => Assert.DoesNotContain(_scenario.CallbackSetCookies, cookie => cookie.StartsWith($"{OidcCallbackAuthProxyFactory.SessionCookieName}C1=", StringComparison.Ordinal) && !cookie.StartsWith($"{OidcCallbackAuthProxyFactory.SessionCookieName}C1=;", StringComparison.Ordinal));
    [Fact] void should_not_set_the_identity_or_tenant_cookies_on_the_callback() => Assert.DoesNotContain(_scenario.CallbackSetCookies, cookie => cookie.StartsWith(".cratis-", StringComparison.Ordinal) && !cookie.Contains("expires=", StringComparison.Ordinal));
    [Fact] void should_delete_this_handshakes_correlation_and_nonce_cookies() => Assert.All(_scenario.CurrentHandshakeCookies, pair => Assert.Contains(_scenario.CallbackSetCookies, cookie => cookie.StartsWith($"{pair.Split('=', 2)[0]}=;", StringComparison.Ordinal)));
    [Fact] void should_keep_the_set_cookie_headers_under_the_warning_threshold() => Assert.True(_scenario.Measurement.SetCookieTotal <= SetCookieSizeMiddleware.WarningThreshold, $"Set-Cookie total {_scenario.Measurement.SetCookieTotal}");
    [Fact] void should_keep_the_response_header_under_a_4k_proxy_buffer() => Assert.True(_scenario.Measurement.HeaderBlock <= CallbackCookieMeasurement.HeaderBlockBudget, $"Header block {_scenario.Measurement.HeaderBlock}");
    [Fact] void should_have_written_handshake_cookies_on_each_challenge() => Assert.NotEmpty(_scenario.StaleHandshakeSetCookies);
    [Fact] void should_let_handshake_cookies_expire_within_an_hour() => Assert.All(_scenario.StaleHandshakeSetCookies, cookie => Assert.True(ExpiresAt(cookie) <= _scenario.StartedAt.AddMinutes(61), cookie.Split('=', 2)[0]));

    static DateTimeOffset ExpiresAt(string setCookie) =>
        Microsoft.Net.Http.Headers.SetCookieHeaderValue.Parse(setCookie).Expires ?? DateTimeOffset.MaxValue;

    [Fact] void should_still_clear_some_stale_handshake_cookies() => Assert.Contains(_scenario.CallbackSetCookies, cookie => _scenario.StaleHandshakeNames.Any(name => cookie.StartsWith($"{name}=;", StringComparison.Ordinal)));
}
