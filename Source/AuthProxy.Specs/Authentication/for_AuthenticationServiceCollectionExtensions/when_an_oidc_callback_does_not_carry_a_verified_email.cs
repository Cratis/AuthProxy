// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a provider requiring a verified e-mail fails the callback, with nothing signed in, whenever the principal does not prove one.
/// </summary>
public class when_an_oidc_callback_does_not_carry_a_verified_email : given.gated_oidc_providers
{
    TicketReceivedContext _unverified;
    TicketReceivedContext _missing;
    TicketReceivedContext _ambiguous;

    async Task Because()
    {
        _unverified = await ReceiveTicket(Context(), "strict", _strictOptions, PrincipalWith(("email", "a@example.com"), ("email_verified", "false")));
        _missing = await ReceiveTicket(Context(), "strict", _strictOptions, PrincipalWith(("email", "a@example.com")));
        _ambiguous = await ReceiveTicket(Context(), "strict", _strictOptions, PrincipalWith(("email", "a@example.com"), ("email", "b@example.com"), ("email_verified", "true")));
    }

    [Fact] void should_fail_an_unverified_callback() => _unverified.Result.Failure.ShouldNotBeNull();
    [Fact] void should_fail_a_callback_without_the_verification() => _missing.Result.Failure.ShouldNotBeNull();
    [Fact] void should_fail_a_callback_with_several_addresses() => _ambiguous.Result.Failure.ShouldNotBeNull();
    [Fact] void should_not_tell_the_notifier_about_a_sign_in() => _notifier.ReceivedCalls().ShouldBeEmpty();
    [Fact] void should_not_record_a_provider_scheme_on_the_refused_principal() => _unverified.Principal!.FindFirst(SessionClaims.ProviderScheme).ShouldBeNull();
}
