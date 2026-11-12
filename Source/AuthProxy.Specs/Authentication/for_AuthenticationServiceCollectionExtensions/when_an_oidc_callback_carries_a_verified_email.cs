// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a verified principal completes as today, and that a provider that does not require verification is never gated.
/// </summary>
public class when_an_oidc_callback_carries_a_verified_email : given.gated_oidc_providers
{
    TicketReceivedContext _verified;
    TicketReceivedContext _relaxedAndUnverified;

    async Task Because()
    {
        _verified = await ReceiveTicket(Context(), "strict", _strictOptions, PrincipalWith(("email", "a@example.com"), ("email_verified", "True")));
        _relaxedAndUnverified = await ReceiveTicket(Context(), "relaxed", _relaxedOptions, PrincipalWith(("email", "a@example.com"), ("email_verified", "false")));
    }

    [Fact] void should_not_fail_a_verified_callback() => (_verified.Result?.Failure is null).ShouldBeTrue();
    [Fact] void should_record_the_provider_scheme_of_a_verified_callback() => _verified.Principal!.FindFirst(SessionClaims.ProviderScheme)!.Value.ShouldEqual("strict");
    [Fact] void should_not_gate_a_provider_that_does_not_require_it() => (_relaxedAndUnverified.Result?.Failure is null).ShouldBeTrue();
}
