// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that an OAuth session matching the current registration is current.
/// </summary>
public class when_evaluating_a_canonical_oauth_session_with_the_current_registration : a_session_policy
{
    CanonicalSessionVerdict _result;

    async Task Because()
    {
        var properties = await IssueCanonicalOAuthTicket();
        UseAuthentication(OAuthAuthentication());
        _result = Evaluate(CanonicalOAuthPrincipal(), properties);
    }

    [Fact] void should_return_current() => _result.ShouldEqual(CanonicalSessionVerdict.Current);
    [Fact] void should_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeTrue();
}
