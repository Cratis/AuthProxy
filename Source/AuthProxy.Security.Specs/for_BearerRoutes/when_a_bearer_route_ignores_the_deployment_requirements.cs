// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A deployment whose claim requirements name a claim the token issuer does not mint would refuse every token on
/// its bearer routes. A route that leaves the deployment's requirements out serves a token that satisfies its own
/// requirements alone, and still refuses one that does not — however well it satisfies the deployment's.
/// </summary>
/// <param name="harness">The running proxy, with claim requirements declared.</param>
[Collection(GatedBearerRouteSpecCollection.Name)]
public class when_a_bearer_route_ignores_the_deployment_requirements(GatedBearerRouteHarness harness) : IAsyncLifetime
{
    const string MemberPath = $"{BearerRouteHarness.ForwardingRoutePrefix}/member";
    const string NotAMemberPath = $"{BearerRouteHarness.ForwardingRoutePrefix}/not-a-member";

    HttpResponseMessage? _member;
    HttpResponseMessage? _notAMember;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        // Neither the proxy-wide organization nor the service's preferred_username: only the route's membership.
        _member = await Send(client, MemberPath, harness.Issuer.Token(new Dictionary<string, object>
        {
            [GatedBearerRouteHarness.MembershipClaim] = GatedBearerRouteHarness.MembershipValue,
            ["preferred_username"] = "someone-else",
        }));

        // Everything the deployment requires, but not the route's membership.
        _notAMember = await Send(client, NotAMemberPath, harness.Issuer.Token(new Dictionary<string, object>
        {
            [GatedBearerRouteHarness.RequiredClaim] = GatedBearerRouteHarness.RequiredValue,
            ["preferred_username"] = BearerRouteHarness.GitHubLogin,
        }));
    }

    public Task DisposeAsync()
    {
        _member?.Dispose();
        _notAMember?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_a_token_satisfying_the_route_requirements() => Assert.Equal(HttpStatusCode.OK, _member!.StatusCode);
    [Fact] public void should_refuse_a_token_missing_the_route_requirement() => Assert.Equal(HttpStatusCode.Forbidden, _notAMember!.StatusCode);
    [Fact] public void should_not_forward_the_refused_token() => Assert.False(harness.Origin.ReceivedAnythingFor(NotAMemberPath));

    static Task<HttpResponseMessage> Send(HttpClient client, string path, string token) =>
        client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, path, token));
}
