// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy;

/// <summary>
/// Several values in one requirement are an <em>or</em>, and the comparison ignores case.
/// <para>
/// The values being matched are organization names, team slugs and role names — identifiers their own
/// systems treat as case-insensitive, and which an operator copies out of a URL or a settings page, where
/// <c>Cratis</c> and <c>cratis</c> are the same thing. An ordinal comparison would turn that into a
/// deployment nobody can sign in to, with a <c>403</c> that says nothing about why.
/// </para>
/// <para>
/// Also pinned here: a caller carrying several claims of the same type — the ordinary case for someone in
/// more than one organization — is satisfied when <em>any</em> of them matches, not only the first.
/// </para>
/// </summary>
public class when_the_claim_carries_one_of_the_allowed_values : given.an_access_policy
{
    C.AuthProxy _config;
    AccessDecision _decision;

    void Establish()
    {
        _config = Requiring(Claiming("urn:github:organization", "Cratis", "Contoso"));
        CallerCarrying(
            new Claim("urn:github:organization", "some-unrelated-org"),
            new Claim("urn:github:organization", "cratis"));
    }

    void Because() => _decision = _policy.Evaluate(_context, _config);

    [Fact] void should_grant_access() => _decision.IsGranted.ShouldBeTrue();
}
