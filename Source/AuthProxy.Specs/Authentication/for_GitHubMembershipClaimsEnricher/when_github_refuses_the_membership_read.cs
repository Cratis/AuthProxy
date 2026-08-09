// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_GitHubMembershipClaimsEnricher;

/// <summary>
/// A membership read that fails leaves the sign-in intact and the claims absent — which is the closed
/// direction, not the open one.
/// <para>
/// This runs inside the sign-in handshake. Throwing would turn a missing claim into a broken login, and
/// the person on the other end would see an authentication error for something that has nothing to do with
/// their credentials. Swallowing it costs nothing, because the outcome of no claims is a caller the gate
/// refuses with an explanation — the fail-closed direction reached the gentle way.
/// </para>
/// <para>
/// GitHub genuinely answers this way: <c>/user/teams</c> is <c>403</c> for a token without the scope, and
/// a network fault mid-handshake looks the same.
/// </para>
/// </summary>
public class when_github_refuses_the_membership_read : given.a_github_provider
{
    GitHubApi _api;
    Exception _error;

    void Establish() => _api = new GitHubApi(url => url.AbsolutePath.EndsWith("/orgs", StringComparison.Ordinal)
        ? GitHubApi.Page("""[{ "login": "Cratis" }]""")
        : GitHubApi.Refused());

    async Task Because()
    {
        using var client = _api.CreateClient();
        _error = await Catch.Exception(() => _enricher.Enrich(_identity, _provider, client, "access-token", CancellationToken.None));
    }

    [Fact] void should_not_break_the_sign_in() => _error.ShouldBeNull();
    [Fact] void should_add_nothing_for_the_read_that_failed() => ValuesOf(GitHubClaimTypes.Team).ShouldBeEmpty();
    [Fact] void should_keep_what_the_read_that_succeeded_returned() => ValuesOf(GitHubClaimTypes.Organization).ShouldContainOnly("Cratis");
}
