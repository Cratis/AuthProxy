// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that registration state without canonical claims is rejected.
/// </summary>
public class when_evaluating_a_session_with_a_fingerprint_but_no_canonical_claims : a_session_policy
{
    CanonicalSessionVerdict _result;

    async Task Because()
    {
        var properties = await IssueCanonicalTicket();
        _result = Evaluate(LegacyPrincipal(), properties);
    }

    [Fact] void should_return_missing_canonical_claims() => _result.ShouldEqual(CanonicalSessionVerdict.MissingCanonicalClaims);
    [Fact] void should_not_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeFalse();
}
