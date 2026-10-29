// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that a principal without any session claim is missing its provider.
/// </summary>
public class when_reading_a_principal_without_a_provider : Specification
{
    bool _result;
    SessionProviderState _state;

    void Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42")], "x"));
        _result = SessionProvider.TryRead(principal, new AuthenticationProperties(), out _);
        _state = SessionProvider.Inspect(principal, new AuthenticationProperties());
    }

    [Fact] void should_not_read_it() => _result.ShouldBeFalse();
    [Fact] void should_be_missing() => _state.ShouldEqual(SessionProviderState.Missing);
}
