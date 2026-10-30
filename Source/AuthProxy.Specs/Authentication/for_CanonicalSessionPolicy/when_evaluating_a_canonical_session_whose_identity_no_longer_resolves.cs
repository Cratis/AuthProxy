// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalSessionPolicy;

/// <summary>
/// Specifies that a session whose canonical identity cannot be resolved is rejected.
/// </summary>
public class when_evaluating_a_canonical_session_whose_identity_no_longer_resolves : a_session_policy
{
    CanonicalSessionVerdict _result;

    async Task Because()
    {
        var properties = await IssueCanonicalTicket();
        _result = Evaluate(
            new ClaimsPrincipal(new ClaimsIdentity([new Claim(CanonicalIdentityClaims.ProviderKey, "unknown-provider")], ProviderScheme)),
            properties);
    }

    [Fact] void should_return_unresolved_identity() => _result.ShouldEqual(CanonicalSessionVerdict.UnresolvedIdentity);
    [Fact] void should_not_accept() => CanonicalSessionPolicy.Accepts(_result).ShouldBeFalse();
}
