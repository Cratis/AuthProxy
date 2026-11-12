// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a provider requiring a verified e-mail ends the callback like an ordinary remote failure, with nothing signed in, whenever the principal does not prove one.
/// </summary>
public class when_an_oidc_callback_does_not_carry_a_verified_email : given.gated_oidc_providers
{
    DefaultHttpContext _unverifiedHttp;
    DefaultHttpContext _remoteFailureHttp;
    TicketReceivedContext _unverified;
    TicketReceivedContext _missing;
    TicketReceivedContext _ambiguous;

    async Task Because()
    {
        _unverifiedHttp = WithHandshakeCookies(Context());
        _unverified = await ReceiveTicket(_unverifiedHttp, "strict", _strictOptions, PrincipalWith(("email", "a@example.com"), ("email_verified", "false")));
        _missing = await ReceiveTicket(Context(), "strict", _strictOptions, PrincipalWith(("email", "a@example.com")));
        _ambiguous = await ReceiveTicket(Context(), "strict", _strictOptions, PrincipalWith(("email", "a@example.com"), ("email", "b@example.com"), ("email_verified", "true")));

        _remoteFailureHttp = WithHandshakeCookies(Context());
        var scheme = new AuthenticationScheme("strict", "strict", typeof(OpenIdConnectHandler));
        await _strictOptions.Events.OnRemoteFailure(new RemoteFailureContext(_remoteFailureHttp, scheme, _strictOptions, new Exception("failed"))
        {
            Properties = new AuthenticationProperties()
        });
    }

    static DefaultHttpContext WithHandshakeCookies(DefaultHttpContext context)
    {
        context.Request.Headers.Cookie = $"{Cookies.CorrelationPrefix}abc=1; {Cookies.NoncePrefix}abc=1";
        return context;
    }

    [Fact] void should_handle_the_response_of_an_unverified_callback() => _unverified.Result.Handled.ShouldBeTrue();
    [Fact] void should_handle_the_response_of_a_callback_without_the_verification() => _missing.Result.Handled.ShouldBeTrue();
    [Fact] void should_handle_the_response_of_a_callback_with_several_addresses() => _ambiguous.Result.Handled.ShouldBeTrue();
    [Fact] void should_not_tell_the_notifier_about_a_sign_in() => _notifier.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_not_record_a_provider_scheme_on_the_refused_principal() => _unverified.Principal!.FindFirst(SessionClaims.ProviderScheme).ShouldBeNull();
    [Fact] void should_redirect_to_the_same_location_as_a_remote_failure() => _unverifiedHttp.Response.Headers.Location.ToString().ShouldEqual(_remoteFailureHttp.Response.Headers.Location.ToString());
    [Fact] void should_redirect_to_provider_selection_with_the_remote_failure_reason() => _unverifiedHttp.Response.Headers.Location.ToString().ShouldContain("remote-failure");
    [Fact] void should_clear_the_same_cookies_as_a_remote_failure() => string.Join('|', _unverifiedHttp.Response.Headers.SetCookie.ToArray()).ShouldEqual(string.Join('|', _remoteFailureHttp.Response.Headers.SetCookie.ToArray()));
    [Fact] void should_clear_cookies_at_all() => _unverifiedHttp.Response.Headers.SetCookie.Count.ShouldNotEqual(0);
}
