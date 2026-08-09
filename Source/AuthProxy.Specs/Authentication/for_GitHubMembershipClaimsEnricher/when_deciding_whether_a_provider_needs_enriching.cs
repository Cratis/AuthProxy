// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_GitHubMembershipClaimsEnricher;

/// <summary>
/// The organization-read scope is the opt-in, and it is the only opt-in.
/// <para>
/// Tying it to the scope rather than to a separate switch avoids the state where the two disagree — a
/// switch turned on without the scope produces empty membership and a deployment nobody can sign in to,
/// while the scope granted without the switch produces claims that were fetched and then not used. GitHub
/// answers <c>/user/orgs</c> with public memberships only and refuses <c>/user/teams</c> outright without
/// it, so the scope is not merely correlated with wanting the claims: it is the condition under which they
/// can be true.
/// </para>
/// <para>
/// It also keeps this off by default and off entirely for everyone else: no scope, no extra request during
/// sign-in, and a provider that is not GitHub is never considered at all.
/// </para>
/// </summary>
public class when_deciding_whether_a_provider_needs_enriching : given.a_github_provider
{
    bool _withReadOrg;
    bool _withAdminOrg;
    bool _withDifferentlyCasedScope;
    bool _withoutAnyOrganizationScope;
    bool _forAnotherProviderBrand;

    void Because()
    {
        _withReadOrg = _enricher.CanEnrich(_provider);

        _provider.Scopes = ["admin:org"];
        _withAdminOrg = _enricher.CanEnrich(_provider);

        _provider.Scopes = [" Read:Org "];
        _withDifferentlyCasedScope = _enricher.CanEnrich(_provider);

        _provider.Scopes = ["read:user", "user:email"];
        _withoutAnyOrganizationScope = _enricher.CanEnrich(_provider);

        _provider.Scopes = ["read:org"];
        _provider.Type = C.OidcProviderType.Custom;
        _forAnotherProviderBrand = _enricher.CanEnrich(_provider);
    }

    [Fact] void should_enrich_when_the_read_scope_is_requested() => _withReadOrg.ShouldBeTrue();
    [Fact] void should_enrich_when_a_wider_organization_scope_is_requested() => _withAdminOrg.ShouldBeTrue();
    [Fact] void should_not_care_about_the_casing_or_padding_of_the_scope() => _withDifferentlyCasedScope.ShouldBeTrue();
    [Fact] void should_stay_out_of_a_sign_in_that_never_asked_for_membership() => _withoutAnyOrganizationScope.ShouldBeFalse();
    [Fact] void should_stay_out_of_a_provider_that_is_not_github() => _forAnotherProviderBrand.ShouldBeFalse();
}
