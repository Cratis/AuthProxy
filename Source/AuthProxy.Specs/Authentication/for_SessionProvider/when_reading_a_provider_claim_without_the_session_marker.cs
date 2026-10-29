// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that a well-formed claim is not trusted when AuthProxy recorded no marker beside it.
/// </summary>
public class when_reading_a_provider_claim_without_the_session_marker : Specification
{
    bool _result;
    SessionProviderState _state;

    void Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(SessionClaims.ProviderScheme, "microsoft")], "x"));
        _result = SessionProvider.TryRead(principal, new AuthenticationProperties(), out _);
        _state = SessionProvider.Inspect(principal, new AuthenticationProperties());
    }

    [Fact] void should_not_trust_the_claim() => _result.ShouldBeFalse();
    [Fact] void should_count_as_having_no_recorded_provider() => _state.ShouldEqual(SessionProviderState.Missing);
}
