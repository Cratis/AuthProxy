// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that an OAuth session is rejected after its registration changes.
/// </summary>
public class when_evaluating_a_canonical_oauth_session_after_its_registration_changes : a_session_policy
{
    CanonicalSessionVerdict _result;

    async Task Because()
    {
        var properties = await IssueCanonicalOAuthTicket();
        UseAuthentication(OAuthAuthentication(tokenEndpoint: "https://changed.example.com/token"));
        _result = Evaluate(CanonicalOAuthPrincipal(), properties);
    }

    [Fact] void should_return_registration_changed() => _result.ShouldEqual(CanonicalSessionVerdict.RegistrationChanged);
    [Fact] void should_not_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeFalse();
}
