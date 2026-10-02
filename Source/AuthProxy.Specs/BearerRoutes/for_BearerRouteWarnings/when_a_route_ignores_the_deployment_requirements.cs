// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteWarnings;

/// <summary>
/// Leaving the deployment's claim requirements out on a bearer route admits callers a browser session would not be
/// admitted as, so it is reported at startup, naming every requirement left out. A route that leaves out nothing —
/// because nothing is declared, or because it does not ask to — is not reported.
/// </summary>
public class when_a_route_ignores_the_deployment_requirements : Specification
{
    BearerRouteWarning[] _ignoring;
    BearerRouteWarning[] _ignoringNothingDeclared;
    BearerRouteWarning[] _applying;

    void Because()
    {
        _ignoring = [.. BearerRouteWarnings.For(Configuration(ignore: true, declareRequirements: true))
            .Where(_ => _.Kind == BearerRouteWarningKind.DeploymentRequirementsIgnored)];
        _ignoringNothingDeclared = [.. BearerRouteWarnings.For(Configuration(ignore: true, declareRequirements: false))
            .Where(_ => _.Kind == BearerRouteWarningKind.DeploymentRequirementsIgnored)];
        _applying = [.. BearerRouteWarnings.For(Configuration(ignore: false, declareRequirements: true))
            .Where(_ => _.Kind == BearerRouteWarningKind.DeploymentRequirementsIgnored)];
    }

    [Fact] void should_report_the_route() => _ignoring.Length.ShouldEqual(1);
    [Fact] void should_name_the_service() => _ignoring[0].ServiceName.ShouldEqual("direct");
    [Fact] void should_name_the_prefix() => _ignoring[0].Prefix.ShouldEqual("/mcp");
    [Fact] void should_name_the_root_and_service_requirements_left_out() => _ignoring[0].Subjects.ShouldContainOnly(["urn:github:team", "urn:github:organization"]);
    [Fact] void should_not_report_a_route_when_nothing_is_required() => _ignoringNothingDeclared.ShouldBeEmpty();
    [Fact] void should_not_report_a_route_applying_the_requirements() => _applying.ShouldBeEmpty();

    static C.AuthProxy Configuration(bool ignore, bool declareRequirements) => new()
    {
        Authorization = declareRequirements
            ? new C.Authorization { RequiredClaims = [new C.ClaimRequirement { Claim = "urn:github:team", AnyOf = ["cratis/core"] }] }
            : new C.Authorization(),
        Services = new Dictionary<string, C.Service>
        {
            ["direct"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://direct.example.test" },
                ResolveIdentityDetails = false,
                Authorization = declareRequirements
                    ? new C.Authorization { RequiredClaims = [new C.ClaimRequirement { Claim = "urn:github:organization", AnyOf = ["cratis"] }] }
                    : null,
                BearerRoutes =
                [
                    new()
                    {
                        PathPrefix = "/mcp",
                        Issuers = [new C.BearerIssuer { Issuer = "https://auth.example.test/" }],
                        Audiences = ["direct-api"],
                        IgnoreDeploymentRequiredClaims = ignore,
                    },
                ],
            },
        },
    };
}
