// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that a session with no canonical state and no recorded provider is a legacy session.
/// </summary>
public class when_evaluating_a_session_without_canonical_state_or_a_canonical_provider : a_session_policy
{
    CanonicalSessionVerdict _result;

    void Because()
    {
        _result = Evaluate(LegacyPrincipal(), new AuthenticationProperties());
    }

    [Fact] void should_return_legacy() => _result.ShouldEqual(CanonicalSessionVerdict.Legacy);
    [Fact] void should_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeTrue();
}
