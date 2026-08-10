// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// Requirements are an <em>and</em>: satisfying most of them is not satisfying them.
/// <para>
/// The alternative reading — any one requirement being enough — is the one that has to be ruled out
/// explicitly, because the two are indistinguishable in a configuration file and produce opposite
/// deployments. Under an <em>or</em>, adding a team requirement to an organization requirement would
/// <em>widen</em> access to anyone in the organization <em>or</em> on the team of any organization, which
/// is the precise opposite of what the person adding it meant.
/// </para>
/// </summary>
public class when_one_of_several_requirements_is_not_satisfied : given.an_access_policy
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
            new Claim("urn:github:team", "Cratis/docs"));
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_deny_access() => _decision.IsGranted.ShouldBeFalse();
    [Fact] void should_name_the_requirement_that_failed() => _decision.UnsatisfiedClaim.ShouldEqual("urn:github:team");
}
