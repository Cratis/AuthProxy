// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// A request whose service is known without reading the request — a bearer route belongs to one service — is held
/// to the root requirements and that service's, never to another service's, and never to fewer because the
/// request names some other service.
/// </summary>
public class when_evaluating_for_a_named_service : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _qualified;
    AccessDecision _missingTheServiceClaim;
    AccessDecision _missingTheRootClaim;
    AccessDecision _forAnotherService;
    AccessDecision _namingAnotherServiceInTheRequest;

    void Establish() => _config = new C.AuthProxy
    {
        Authorization = new C.Authorization { RequiredClaims = [Claiming("org", "Cratis")] },
        Services = new Dictionary<string, C.Service>
        {
            ["admin"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "http://admin.test/" },
                Authorization = new C.Authorization { RequiredClaims = [Claiming("team", "operations")] },
            },
            ["portal"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "http://portal.test/" },
            },
        },
    };

    void Because()
    {
        var qualified = Principal(new Claim("org", "cratis"), new Claim("team", "Operations"));
        var orgOnly = Principal(new Claim("org", "Cratis"));
        var teamOnly = Principal(new Claim("team", "operations"));

        _qualified = _policy.Evaluate(qualified, _config, "admin");
        _missingTheServiceClaim = _policy.Evaluate(orgOnly, _config, "admin");
        _missingTheRootClaim = _policy.Evaluate(teamOnly, _config, "portal");
        _forAnotherService = _policy.Evaluate(orgOnly, _config, "portal");

        _context.Request.Headers[Headers.ServiceId] = "portal";
        _namingAnotherServiceInTheRequest = _policy.Evaluate(orgOnly, _config, "ADMIN");
    }

    [Fact] void should_grant_a_caller_satisfying_the_root_and_the_service() => _qualified.IsGranted.ShouldBeTrue();
    [Fact] void should_deny_a_caller_missing_the_service_requirement() => _missingTheServiceClaim.UnsatisfiedClaim.ShouldEqual("team");
    [Fact] void should_deny_a_caller_missing_the_root_requirement() => _missingTheRootClaim.UnsatisfiedClaim.ShouldEqual("org");
    [Fact] void should_not_apply_another_service_requirements() => _forAnotherService.IsGranted.ShouldBeTrue();
    [Fact] void should_ignore_what_the_request_names() => _namingAnotherServiceInTheRequest.IsGranted.ShouldBeFalse();

    static ClaimsPrincipal Principal(params Claim[] claims) => new(new ClaimsIdentity(claims, "spec"));
}
