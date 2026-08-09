// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_requiring_claims;

/// <summary>
/// A requirement scoped to a service is written under that service, and numbered per service.
/// <para>
/// Numbering that continued across services would put one service's requirement at another's index, which
/// binds as a requirement on the wrong traffic — an admin surface left open while an unrelated service
/// demands a claim nobody has. Requiring the same claim of everything and of one service at once has to
/// stay two independent sequences.
/// </para>
/// </summary>
public class and_they_are_required_of_one_service : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithRequiredClaim("urn:github:organization", "Cratis");
        _resource.WithRequiredClaimForService("admin", "urn:github:team", "Cratis/operations");
        _resource.WithRequiredClaimForService("admin", "urn:example:mfa");
        _resource.WithRequiredClaimForService("portal", "urn:github:team", "Cratis/support");
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_write_the_service_requirement_under_that_service() => _environment["Cratis__AuthProxy__Services__admin__Authorization__RequiredClaims__0__Claim"].ShouldEqual("urn:github:team");
    [Fact] void should_append_within_the_same_service() => _environment["Cratis__AuthProxy__Services__admin__Authorization__RequiredClaims__1__Claim"].ShouldEqual("urn:example:mfa");
    [Fact] void should_number_each_service_independently() => _environment["Cratis__AuthProxy__Services__portal__Authorization__RequiredClaims__0__AnyOf__0"].ShouldEqual("Cratis/support");
    [Fact] void should_keep_the_proxy_wide_requirement_at_its_own_index() => _environment["Cratis__AuthProxy__Authorization__RequiredClaims__0__Claim"].ShouldEqual("urn:github:organization");
    [Fact] void should_write_no_values_for_a_presence_only_requirement() => _environment.Keys.ShouldNotContain("Cratis__AuthProxy__Services__admin__Authorization__RequiredClaims__1__AnyOf__0");
}
