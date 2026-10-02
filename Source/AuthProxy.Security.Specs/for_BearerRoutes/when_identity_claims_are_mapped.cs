// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// Mapped identity fields are single-valued and cannot be overridden by a surviving case variant.
/// </summary>
/// <param name="harness">The proxy mapping the GitHub identity.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_identity_claims_are_mapped(BearerRouteHarness harness)
{
    [Theory]
    [InlineData("github_id")]
    [InlineData("github_login")]
    public async Task should_refuse_multiple_values_for_a_mapped_identity_field(string source)
    {
        using var client = harness.CreateBearerClient();
        var path = $"/mcp/multiple-{source}";
        harness.Origin.Clear();
        using var response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(new Dictionary<string, object>
        {
            [source] = new[] { "one", "two" },
        })));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("invalid_token", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
        Assert.False(harness.Origin.ReceivedAnythingFor(path));
    }

    [Fact]
    public async Task should_replace_all_case_variants_of_mapped_identity_claims()
    {
        using var client = harness.CreateBearerClient();
        const string path = "/mcp/case-variant-subject";
        using var response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(new Dictionary<string, object>
        {
            ["SUB"] = "another-user",
            ["PREFERRED_USERNAME"] = "another-name",
        })));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var forwarded = harness.Origin.LastRequestTo(path)!;
        Assert.Equal(BearerRouteHarness.GitHubId, forwarded.Value(Headers.PrincipalId));
        Assert.Equal(BearerRouteHarness.GitHubLogin, forwarded.Value(Headers.PrincipalName));
        Assert.True(ClientPrincipal.TryFromBase64(forwarded.Value(Headers.Principal), out var principal));
        Assert.Single(principal!.Claims, _ => string.Equals(_.Type, "sub", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(principal.Claims, _ => _.Type == "SUB" || _.Type == "PREFERRED_USERNAME");
    }

    [Fact]
    public async Task should_read_unmapped_jwt_identity_fields_with_ordinal_comparison()
    {
        using var client = harness.CreateBearerClient();
        const string path = "/v1/case-variant-subject";
        var token = harness.Issuer.TokenShaped(_ => _.Claims = new Dictionary<string, object>
        {
            ["SUB"] = "another-user",
            ["PREFERRED_USERNAME"] = "another-name",
        }.Concat(StubIssuer.DefaultClaims()).ToDictionary(_ => _.Key, _ => _.Value));
        using var response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, path, token));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var forwarded = harness.Origin.LastRequestTo(path)!;
        Assert.Equal(BearerRouteHarness.AccountId, forwarded.Value(Headers.PrincipalId));
        Assert.Equal(BearerRouteHarness.GitHubLogin, forwarded.Value(Headers.PrincipalName));
    }
}
