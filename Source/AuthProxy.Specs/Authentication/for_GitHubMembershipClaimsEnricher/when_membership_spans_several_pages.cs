// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_GitHubMembershipClaimsEnricher;

/// <summary>
/// Paging is followed, and only within the host the read started from.
/// <para>
/// GitHub pages every collection and links the next page from a <c>Link</c> header rather than from the
/// body, so a read that stopped at the first response would answer "the first hundred organizations" — a
/// different question from the one authorization is asking, and one whose wrong answer is a member being
/// refused for a reason nothing in the configuration explains.
/// </para>
/// <para>
/// The link is a URL out of a response, so it is followed only while it stays on the same host. Without
/// that, a spoofed or compromised response could walk the proxy's authenticated back channel — carrying
/// the user's access token — to a host of its choosing.
/// </para>
/// </summary>
public class when_membership_spans_several_pages : given.a_github_provider
{
    GitHubApi _api;

    void Establish() => _api = new GitHubApi(url => url switch
    {
        _ when url.AbsolutePath.EndsWith("/teams", StringComparison.Ordinal) =>
            GitHubApi.Page("[]", "https://exfiltration.test/user/teams?page=2"),
        _ when url.Query.Contains("page=2", StringComparison.Ordinal) =>
            GitHubApi.Page("""[{ "login": "Contoso" }]"""),
        _ =>
            GitHubApi.Page("""[{ "login": "Cratis" }]""", "https://api.github.com/user/orgs?per_page=100&page=2"),
    });

    async Task Because()
    {
        using var client = _api.CreateClient();
        await _enricher.Enrich(_identity, _provider, client, "access-token", CancellationToken.None);
    }

    [Fact] void should_keep_the_first_page() => ValuesOf(GitHubClaimTypes.Organization).ShouldContain("Cratis");
    [Fact] void should_follow_the_link_to_the_next_page() => ValuesOf(GitHubClaimTypes.Organization).ShouldContain("Contoso");
    [Fact] void should_not_follow_a_link_to_another_host() => _api.Requested.ShouldNotContain(_ => _.Host.Equals("exfiltration.test", StringComparison.Ordinal));
    [Fact] void should_ask_for_the_largest_page_github_will_return() => _api.Requested[0].Query.ShouldContain("per_page=100");
}
