// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A caller with a valid token cannot add to what the token says: every inbound copy of a header the backend
/// trusts is replaced by what AuthProxy vouches for, and one the token does not supply is not forwarded at all.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_identity_headers_are_spoofed_on_a_bearer_route(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";

    ForwardedRequest? _forwarded;
    string _forgedPrincipal = string.Empty;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _forgedPrincipal = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """{"userId":"attacker","userRoles":["Administrator"]}"""));

        var request = BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.Token(without: "azp"));
        request.Headers.TryAddWithoutValidation(Headers.Principal, _forgedPrincipal);
        request.Headers.TryAddWithoutValidation(Headers.PrincipalId, "attacker");
        request.Headers.TryAddWithoutValidation(Headers.PrincipalName, "attacker");
        request.Headers.TryAddWithoutValidation(Headers.PrincipalNameExtended, "UTF-8''attacker");
        request.Headers.TryAddWithoutValidation(Headers.TenantId, "victim-tenant");
        request.Headers.TryAddWithoutValidation(Headers.TokenScope, "direct:admin");
        request.Headers.TryAddWithoutValidation(Headers.TokenClientId, "trusted-client");

        using var response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(Path);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_request() => Assert.NotNull(_forwarded);
    [Fact] public void should_replace_the_principal() => Assert.NotEqual(_forgedPrincipal, _forwarded!.Value(Headers.Principal));
    [Fact] public void should_replace_the_principal_id() => Assert.Equal(BearerRouteHarness.GitHubId, _forwarded!.Value(Headers.PrincipalId));
    [Fact] public void should_replace_the_principal_name() => Assert.Equal(BearerRouteHarness.GitHubLogin, _forwarded!.Value(Headers.PrincipalName));
    [Fact] public void should_drop_the_extended_principal_name() => Assert.False(_forwarded!.Has(Headers.PrincipalNameExtended));
    [Fact] public void should_replace_the_tenant() => Assert.Equal(BearerRouteHarness.TenantId, _forwarded!.Value(Headers.TenantId));
    [Fact] public void should_replace_the_scopes() => Assert.Equal("direct:read direct:work", _forwarded!.Value(Headers.TokenScope));
    [Fact] public void should_take_the_client_from_the_token_alone() => Assert.Equal(BearerRouteHarness.ClientId, _forwarded!.Value(Headers.TokenClientId));
}
