// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that blank and untrimmed provider values are malformed.
/// </summary>
public class when_reading_a_blank_provider : Specification
{
    SessionProviderState _blank;
    SessionProviderState _untrimmed;

    void Because()
    {
        _blank = SessionProvider.Inspect(new ClaimsPrincipal(new ClaimsIdentity([new Claim(SessionClaims.ProviderScheme, " ")], "x")), new AuthenticationProperties(new Dictionary<string, string?> { [SessionProvider.MarkerStateKey] = " " }));
        _untrimmed = SessionProvider.Inspect(new ClaimsPrincipal(new ClaimsIdentity([new Claim(SessionClaims.ProviderScheme, " microsoft")], "x")), new AuthenticationProperties(new Dictionary<string, string?> { [SessionProvider.MarkerStateKey] = " microsoft" }));
    }

    [Fact] void should_treat_a_blank_value_as_malformed() => _blank.ShouldEqual(SessionProviderState.Malformed);
    [Fact] void should_treat_an_untrimmed_value_as_malformed() => _untrimmed.ShouldEqual(SessionProviderState.Malformed);
}
