// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_requiring_claims;

/// <summary>
/// Proxy-wide requirements reach the proxy as the indexed environment variables its configuration binds.
/// <para>
/// The key shape is the contract between the app host and the proxy, and it is the one thing about this
/// feature that fails silently: a wrong prefix, separator or index binds nothing, and a proxy that
/// requires nothing looks exactly like a proxy that is working. The symptom would be an account that
/// should have been refused quietly getting in.
/// </para>
/// <para>
/// Repeated calls append rather than restart at zero — the indices are positions in a configuration array,
/// so a second call that overwrote the first would drop a requirement while the app host still read as
/// though both were declared.
/// </para>
/// </summary>
public class and_they_are_required_of_every_service : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithRequiredClaim("urn:github:organization", "Cratis");
        _resource.WithRequiredClaim("urn:github:team", "Cratis/planner", "Cratis/operations");
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_write_the_first_claim_at_the_first_index() => _environment["Cratis__AuthProxy__Authorization__RequiredClaims__0__Claim"].ShouldEqual("urn:github:organization");
    [Fact] void should_write_its_only_value() => _environment["Cratis__AuthProxy__Authorization__RequiredClaims__0__AnyOf__0"].ShouldEqual("Cratis");
    [Fact] void should_append_the_second_claim_rather_than_overwrite_the_first() => _environment["Cratis__AuthProxy__Authorization__RequiredClaims__1__Claim"].ShouldEqual("urn:github:team");
    [Fact] void should_write_each_of_its_values() => _environment["Cratis__AuthProxy__Authorization__RequiredClaims__1__AnyOf__1"].ShouldEqual("Cratis/operations");
}
