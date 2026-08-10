// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// A service's requirements are added to the proxy-wide ones, never substituted for them.
/// <para>
/// A service can therefore only narrow who reaches it. The substituting reading is the dangerous one: it
/// would make the root a default rather than a floor, so a service section written to add an
/// administrator check would quietly <em>drop</em> the organization check, and a service added later with
/// no section at all would be the way in.
/// </para>
/// <para>
/// The request here names no service — this is a single-service deployment, where everything routes to the
/// one service, exactly as the route table's catch-all does.
/// </para>
/// </summary>
public class when_a_service_declares_its_own_requirements : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _satisfyingBoth;
    AccessDecision _satisfyingOnlyTheServiceOne;
    AccessDecision _satisfyingOnlyTheGlobalOne;

    void Establish() => _config = new C.AuthProxy
    {
        Authorization = new C.Authorization { RequiredClaims = [Claiming("urn:github:organization", "Cratis")] },
        Services = new Dictionary<string, C.Service>
        {
            ["main"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                Authorization = new C.Authorization { RequiredClaims = [Claiming("urn:github:team", "Cratis/planner")] },
            },
        },
    };

    void Because()
    {
        CallerCarrying(new Claim("urn:github:organization", "Cratis"), new Claim("urn:github:team", "Cratis/planner"));
        _satisfyingBoth = _policy.Evaluate(_context, _config);

        CallerCarrying(new Claim("urn:github:team", "Cratis/planner"));
        _satisfyingOnlyTheServiceOne = _policy.Evaluate(_context, _config);

        CallerCarrying(new Claim("urn:github:organization", "Cratis"));
        _satisfyingOnlyTheGlobalOne = _policy.Evaluate(_context, _config);
    }

    [Fact] void should_consider_authorization_configured() => _policy.IsConfigured(_config).ShouldBeTrue();
    [Fact] void should_grant_a_caller_satisfying_both() => _satisfyingBoth.IsGranted.ShouldBeTrue();
    [Fact] void should_still_apply_the_proxy_wide_requirement() => _satisfyingOnlyTheServiceOne.IsGranted.ShouldBeFalse();
    [Fact] void should_also_apply_the_service_requirement() => _satisfyingOnlyTheGlobalOne.IsGranted.ShouldBeFalse();
    [Fact] void should_name_the_service_requirement_when_that_is_the_one_missing() => _satisfyingOnlyTheGlobalOne.UnsatisfiedClaim.ShouldEqual("urn:github:team");
}
