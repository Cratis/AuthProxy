// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// A deployment can require a claim only its browser sign-in produces — a GitHub team, read from the GitHub API —
/// which the token issuer does not mint. A bearer route that says so leaves the root and service requirements out,
/// and is held to its own instead. Its own requirements apply whether or not it leaves the deployment's out.
/// </summary>
public class when_a_bearer_route_ignores_the_deployment_requirements : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _memberWithoutTheTeam;
    AccessDecision _teamWithoutTheMembership;
    AccessDecision _byDefault;
    AccessDecision _ownRequirementsOnTopOfTheDeployment;

    void Establish() => _config = new C.AuthProxy
    {
        Authorization = new C.Authorization { RequiredClaims = [Claiming("urn:github:team", "cratis/core")] },
        Services = new Dictionary<string, C.Service>
        {
            ["direct"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "http://direct.test/" },
                Authorization = new C.Authorization { RequiredClaims = [Claiming("urn:github:organization", "cratis")] },
            },
        },
    };

    void Because()
    {
        var ignoring = new C.BearerRoute
        {
            IgnoreDeploymentRequiredClaims = true,
            RequiredClaims = [Claiming("membership", "direct")],
        };
        var applying = new C.BearerRoute { RequiredClaims = [Claiming("membership", "direct")] };

        var member = Principal(new Claim("membership", "direct"));
        var team = Principal(new Claim("urn:github:team", "cratis/core"), new Claim("urn:github:organization", "cratis"));

        _memberWithoutTheTeam = _policy.Evaluate(member, _config, "direct", ignoring);
        _teamWithoutTheMembership = _policy.Evaluate(team, _config, "direct", ignoring);
        _byDefault = _policy.Evaluate(member, _config, "direct", new C.BearerRoute());
        _ownRequirementsOnTopOfTheDeployment = _policy.Evaluate(team, _config, "direct", applying);
    }

    [Fact] void should_grant_a_caller_satisfying_the_route_requirements_alone() => _memberWithoutTheTeam.IsGranted.ShouldBeTrue();
    [Fact] void should_deny_a_caller_missing_the_route_requirement() => _teamWithoutTheMembership.UnsatisfiedClaim.ShouldEqual("membership");
    [Fact] void should_apply_the_deployment_requirements_by_default() => _byDefault.UnsatisfiedClaim.ShouldEqual("urn:github:team");
    [Fact] void should_add_the_route_requirements_to_the_deployment_requirements() => _ownRequirementsOnTopOfTheDeployment.UnsatisfiedClaim.ShouldEqual("membership");

    static ClaimsPrincipal Principal(params Claim[] claims) => new(new ClaimsIdentity(claims, "spec"));
}
