// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A valid access token on a bearer route is the whole credential: the request is forwarded with the identity a
/// browser session of the same deployment would carry — the GitHub id and login, through the route's claim
/// mappings — the tenant the token names, and the scopes and client the token was issued with. The token itself,
/// and any cookie, stay at the edge.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_a_valid_token_is_presented(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";

    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;
    ClientPrincipal? _principal;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        var request = BearerRouteHarness.WithToken(HttpMethod.Post, Path, harness.Issuer.Token());
        request.Headers.TryAddWithoutValidation("Cookie", ".cratis-session=some-session");
        _response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(Path);

        ClientPrincipal.TryFromBase64(_forwarded?.Value(Headers.Principal), out _principal);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_answer_with_the_origin_response() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_forward_the_request() => Assert.NotNull(_forwarded);
    [Fact] public void should_forward_the_github_id_as_the_principal_id() => Assert.Equal(BearerRouteHarness.GitHubId, _forwarded!.Value(Headers.PrincipalId));
    [Fact] public void should_forward_the_github_login_as_the_principal_name() => Assert.Equal(BearerRouteHarness.GitHubLogin, _forwarded!.Value(Headers.PrincipalName));
    [Fact] public void should_forward_the_tenant_from_the_token() => Assert.Equal(BearerRouteHarness.TenantId, _forwarded!.Value(Headers.TenantId));
    [Fact] public void should_forward_the_granted_scopes() => Assert.Equal("direct:read direct:work", _forwarded!.Value(Headers.TokenScope));
    [Fact] public void should_forward_the_client_the_token_was_issued_to() => Assert.Equal(BearerRouteHarness.ClientId, _forwarded!.Value(Headers.TokenClientId));
    [Fact] public void should_name_the_route_identity_provider() => Assert.Equal("github", _principal!.IdentityProvider);
    [Fact] public void should_keep_the_account_id_in_the_principal() => Assert.Contains(_principal!.Claims, _ => _.Type == "urn:cratis:bearer:subject" && _.Value == BearerRouteHarness.AccountId);
    [Fact] public void should_not_forward_the_token() => Assert.False(_forwarded!.Has("Authorization"));
    [Fact] public void should_not_forward_the_cookie() => Assert.False(_forwarded!.Has("Cookie"));
}
