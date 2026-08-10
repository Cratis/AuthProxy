// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// Carrying the claim is not the same as carrying an accepted value.
/// <para>
/// A GitHub account belongs to organizations, so the claim is there for everybody who signs in — it is the
/// value that separates the people who work here from everybody else. A check that stopped at presence
/// would let the entire internet through while looking, in configuration, exactly like a check that did
/// not.
/// </para>
/// </summary>
public class when_the_claim_carries_a_value_that_is_not_allowed : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _decision;

    void Establish()
    {
        _config = Requiring(Claiming("urn:github:organization", "Cratis"));
        CallerCarrying(new Claim("urn:github:organization", "some-other-org"));
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_deny_access() => _decision.IsGranted.ShouldBeFalse();
    [Fact] void should_name_the_claim_that_was_not_satisfied() => _decision.UnsatisfiedClaim.ShouldEqual("urn:github:organization");
}
