// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that a claim disagreeing with AuthProxy's marker is not trusted.
/// </summary>
public class when_reading_a_provider_claim_that_differs_from_the_session_marker : Specification
{
    bool _result;
    SessionProviderState _state;

    void Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(SessionClaims.ProviderScheme, "github")], "x"));
        var properties = new AuthenticationProperties(new Dictionary<string, string?> { [SessionProvider.MarkerStateKey] = "microsoft" });
        _result = SessionProvider.TryRead(principal, properties, out _);
        _state = SessionProvider.Inspect(principal, properties);
    }

    [Fact] void should_not_trust_the_claim() => _result.ShouldBeFalse();
    [Fact] void should_be_malformed() => _state.ShouldEqual(SessionProviderState.Malformed);
}
