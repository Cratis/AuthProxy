// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that more than one provider claim is malformed.
/// </summary>
public class when_reading_a_duplicated_provider : Specification
{
    bool _result;
    SessionProviderState _state;

    void Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(SessionClaims.ProviderScheme, "microsoft"), new Claim(SessionClaims.ProviderScheme, "github")],
            "x"));
        _result = SessionProvider.TryRead(principal, out _);
        _state = SessionProvider.Inspect(principal);
    }

    [Fact] void should_not_read_it() => _result.ShouldBeFalse();
    [Fact] void should_be_malformed() => _state.ShouldEqual(SessionProviderState.Malformed);
}
