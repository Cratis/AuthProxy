// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_GitHubMembershipClaimsEnricher;

/// <summary>
/// Organizations and teams come back as ordinary claims, so the ordinary claim requirements can gate on
/// them.
/// <para>
/// This is the piece that makes gating on a GitHub organization possible at all: GitHub's user endpoint
/// returns a profile and nothing about membership, so there is no claim to require and no field mapping
/// that could invent one. Fetching it here and adding it as a claim is what keeps a single authorization
/// mechanism rather than a second, GitHub-shaped one — and it hands the application the same membership on
/// the forwarded principal.
/// </para>
/// <para>
/// A team claim is qualified by its organization because a slug is only unique within one: two
/// organizations may both have a <c>planner</c> team, and an unqualified claim would let membership of
/// either satisfy a requirement written for one. The endpoints are derived from the configured user
/// endpoint, which is what lets GitHub Enterprise work without another setting.
/// </para>
/// </summary>
public class when_reading_membership : given.a_github_provider
{
    GitHubApi _api;

    void Establish() => _api = new GitHubApi(url => url.AbsolutePath.EndsWith("/orgs", StringComparison.Ordinal)
        ? GitHubApi.Page("""[{ "login": "Cratis" }, { "login": "Contoso" }]""")
        : GitHubApi.Page("""[{ "slug": "planner", "organization": { "login": "Cratis" } }]"""));

    async Task Because()
    {
        using var client = _api.CreateClient();
        await _enricher.Enrich(_identity, _provider, client, "access-token", CancellationToken.None);
    }

    [Fact] void should_add_a_claim_per_organization() => ValuesOf(GitHubClaimTypes.Organization).ShouldContainOnly("Cratis", "Contoso");
    [Fact] void should_qualify_a_team_by_its_organization() => ValuesOf(GitHubClaimTypes.Team).ShouldContainOnly("Cratis/planner");
    [Fact] void should_read_the_organizations_under_the_configured_user_endpoint() => _api.Requested.ShouldContain(_ => _.AbsoluteUri.StartsWith("https://api.github.com/user/orgs", StringComparison.Ordinal));
    [Fact] void should_read_the_teams_under_the_configured_user_endpoint() => _api.Requested.ShouldContain(_ => _.AbsoluteUri.StartsWith("https://api.github.com/user/teams", StringComparison.Ordinal));
    [Fact] void should_leave_the_claims_the_identity_arrived_with() => _identity.FindFirst(ClaimTypes.Name)!.Value.ShouldEqual("octocat");
}
