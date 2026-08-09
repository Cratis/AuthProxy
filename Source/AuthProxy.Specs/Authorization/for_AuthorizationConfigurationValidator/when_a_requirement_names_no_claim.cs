// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AuthorizationConfigurationValidator;

/// <summary>
/// A requirement with no claim type fails startup, naming exactly where it is.
/// <para>
/// The alternative outcomes are both bad in ways that are hard to diagnose. Starting and applying it means
/// every caller is refused, because nothing satisfies a requirement for nothing — a total outage caused by
/// an environment variable that failed to interpolate. Starting and ignoring it means the gate is silently
/// open, which is the failure this feature exists to close. Refusing to start is the only answer that
/// happens while somebody is watching.
/// </para>
/// </summary>
public class when_a_requirement_names_no_claim : Specification
{
    AuthorizationConfigurationValidator _validator;
    C.AuthProxy _config;
    ValidateOptionsResult _result;

    void Establish()
    {
        _validator = new AuthorizationConfigurationValidator();
        _config = new C.AuthProxy
        {
            Authorization = new C.Authorization
            {
                RequiredClaims =
                [
                    new C.ClaimRequirement { Claim = "urn:github:organization", AnyOf = ["Cratis"] },
                    new C.ClaimRequirement { Claim = string.Empty, AnyOf = ["Cratis/planner"] },
                ],
            },
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new()
                {
                    Authorization = new C.Authorization { RequiredClaims = [new C.ClaimRequirement { Claim = "  " }] },
                },
            },
        };
    }

    void Because() => _result = _validator.Validate(null, _config);

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_point_at_the_offending_proxy_wide_requirement() => _result.Failures.ShouldContain(_ => _.Contains("Cratis:AuthProxy:Authorization:RequiredClaims:1:Claim", StringComparison.Ordinal));
    [Fact] void should_point_at_the_offending_service_requirement() => _result.Failures.ShouldContain(_ => _.Contains("Cratis:AuthProxy:Services:main:Authorization:RequiredClaims:0:Claim", StringComparison.Ordinal));
    [Fact] void should_not_complain_about_the_usable_requirement() => _result.Failures.Count().ShouldEqual(2);
}
