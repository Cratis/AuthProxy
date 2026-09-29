// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A token cannot grant a role or speak in AuthProxy's own claim namespaces: its role claims are dropped, the only
/// roles forwarded are <c language="text">anonymous</c> and <c language="text">authenticated</c>, and <c language="text">urn:cratis:bearer:</c>
/// and <c language="text">urn:cratis:identity:</c> claims carry only what AuthProxy itself wrote. A token that names no client
/// forwards no client header, whatever the caller sent.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_token_carries_claims_it_may_not_forward(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/claims";

    ForwardedRequest? _forwarded;
    ClientPrincipal? _principal;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        var token = harness.Issuer.Token(
            new Dictionary<string, object>
            {
                ["roles"] = new[] { "Administrator" },
                ["role"] = "Administrator",
                ["urn:cratis:bearer:scope"] = "direct:admin",
                ["urn:cratis:bearer:client-id"] = "trusted-client",
                ["urn:cratis:identity:subject"] = "someone-else",
            },
            without: ["azp", "client_id"]);

        var request = BearerRouteHarness.WithToken(HttpMethod.Get, Path, token);
        request.Headers.TryAddWithoutValidation(Headers.TokenClientId, "trusted-client");

        using var response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(Path);
        ClientPrincipal.TryFromBase64(_forwarded?.Value(Headers.Principal), out _principal);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_request() => Assert.NotNull(_principal);
    [Fact] public void should_grant_no_role() => Assert.Equal(["anonymous", "authenticated"], _principal!.UserRoles);
    [Fact] public void should_drop_the_role_claims() => Assert.DoesNotContain(_principal!.Claims, _ => string.Equals(_.Type, "roles", StringComparison.Ordinal) || string.Equals(_.Type, "role", StringComparison.Ordinal) || _.Type.EndsWith("/role", StringComparison.Ordinal));
    [Fact] public void should_forward_only_the_scopes_it_validated() =>
        Assert.Equal(["direct:read", "direct:work"], _principal!.Claims.Where(_ => _.Type == "urn:cratis:bearer:scope").Select(_ => _.Value).Order());
    [Fact] public void should_forward_no_client_claim() => Assert.DoesNotContain(_principal!.Claims, _ => _.Type == "urn:cratis:bearer:client-id");
    [Fact] public void should_drop_the_canonical_identity_claims() => Assert.DoesNotContain(_principal!.Claims, _ => _.Type.StartsWith("urn:cratis:identity:", StringComparison.Ordinal));
    [Fact] public void should_forward_no_client_header() => Assert.False(_forwarded!.Has(Headers.TokenClientId));
}
