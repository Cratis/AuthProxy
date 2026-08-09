// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// Several requirements compose as an <em>and</em>, and a caller satisfying all of them gets in.
/// <para>
/// This is the shape the GitHub case is written in: one requirement for the organization, one for the
/// team. Splitting it that way is what lets the organization requirement stand on its own if the team is
/// later dropped, and it is why the two axes are separate requirements rather than a single compound
/// value.
/// </para>
/// </summary>
public class when_every_requirement_is_satisfied : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _decision;

    void Establish()
    {
        _config = Requiring(
            Claiming("urn:github:organization", "Cratis"),
            Claiming("urn:github:team", "Cratis/planner"));

        CallerCarrying(
            new Claim("urn:github:organization", "Cratis"),
            new Claim("urn:github:team", "Cratis/planner"),
            new Claim("urn:github:team", "Cratis/docs"));
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_grant_access() => _decision.IsGranted.ShouldBeTrue();
}
