// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that a single well-formed claim is read back as recorded.
/// </summary>
public class when_reading_a_recorded_provider : Specification
{
    bool _result;
    string _scheme;
    SessionProviderState _state;

    void Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(SessionClaims.ProviderScheme, "microsoft")], "x"));
        _result = SessionProvider.TryRead(principal, out _scheme);
        _state = SessionProvider.Inspect(principal);
    }

    [Fact] void should_read_it() => _result.ShouldBeTrue();
    [Fact] void should_return_the_scheme() => _scheme.ShouldEqual("microsoft");
    [Fact] void should_be_recorded() => _state.ShouldEqual(SessionProviderState.Recorded);
}
