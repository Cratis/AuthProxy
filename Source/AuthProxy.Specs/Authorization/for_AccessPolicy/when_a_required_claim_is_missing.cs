// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// The whole point: an authenticated caller carrying nothing that satisfies the requirement is refused.
/// <para>
/// This is the case that motivates the feature. Sign-in succeeded — the caller is a real, verified account
/// at a real identity provider — and that says nothing about whether this deployment is theirs to reach.
/// The refusal names the claim, so a refusal in a log is something an operator can act on rather than a
/// bare "denied"; it names the claim <em>type</em> and never the caller's value, which would put an
/// identity into the log to explain that it was turned away.
/// </para>
/// </summary>
public class when_a_required_claim_is_missing : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _decision;

    void Establish()
    {
        _config = Requiring(Claiming("urn:github:organization", "Cratis"));
        CallerCarrying(
            new Claim(ClaimTypes.NameIdentifier, "some-github-user"),
            new Claim(ClaimTypes.Name, "octocat"));
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_deny_access() => _decision.IsGranted.ShouldBeFalse();
    [Fact] void should_name_the_claim_that_was_not_satisfied() => _decision.UnsatisfiedClaim.ShouldEqual("urn:github:organization");
}
