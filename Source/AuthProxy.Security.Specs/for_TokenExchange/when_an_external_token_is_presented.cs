// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace Cratis.AuthProxy.Security.for_TokenExchange;

public class when_an_external_token_is_presented
{
    [Fact]
    public async Task should_forward_only_the_validated_identity_result()
    {
        await using var harness = new TokenExchangeHarness();
        var exchanged = harness.Exchanged();
        harness.Result = () => exchanged;
        using var client = harness.CreateBearerClient();
        var subject = harness.Subject();
        using var request = Request(subject);
        request.Headers.TryAddWithoutValidation("X-Cratis-Tenant-Id", "attacker");
        request.Headers.TryAddWithoutValidation("X-Cratis-Subject", "attacker");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, harness.Calls);
        var form = QueryHelpers.ParseQuery(harness.Form);
        Assert.Equal("https://cratis.direct/mcp", form["resource"].ToString());
        Assert.Equal("tenant-a", form["tenant"].ToString());
        var forwarded = harness.Origin.LastRequestTo(BearerRouteHarness.RoutePrefix);
        Assert.Equal("Bearer " + exchanged, forwarded.Value("Authorization"));
        Assert.Equal("tenant-a", forwarded.Value(Headers.TenantId));
        var principal = Encoding.UTF8.GetString(Convert.FromBase64String(forwarded.Value(Headers.Principal)));
        Assert.Contains("identity-subject", principal);
        Assert.DoesNotContain("external-subject", principal);
    }

    [Theory]
    [InlineData("resource-audience")]
    [InlineData("wrong-audience")]
    [InlineData("wrong-tenant")]
    [InlineData("case-tenant")]
    [InlineData("missing-idp")]
    [InlineData("wrong-idp")]
    [InlineData("wrong-issuer")]
    [InlineData("bad-signature")]
    [InlineData("expired")]
    [InlineData("missing-scope")]
    [InlineData("bound-token")]
    [InlineData("missing-tenant")]
    [InlineData("several-tenants")]
    [InlineData("unusable-tenant")]
    [InlineData("tenant-id-only")]
    public async Task should_refuse_a_hostile_exchange_result_and_evict_it(string hostile)
    {
        await using var harness = new TokenExchangeHarness();
        var result = Hostile(harness, hostile);
        harness.Result = () => result;
        using var client = harness.CreateBearerClient();
        var subject = harness.Subject();
        using var first = await client.SendAsync(Request(subject), TestContext.Current.CancellationToken);
        var forbidden = new[] { "wrong-tenant", "case-tenant", "missing-idp", "wrong-idp", "missing-scope" }.Contains(hostile, StringComparer.Ordinal);
        Assert.Equal(forbidden ? HttpStatusCode.Forbidden : HttpStatusCode.Unauthorized, first.StatusCode);
        Assert.True(first.Headers.CacheControl!.NoStore);
        Assert.Empty(harness.Origin.Received);
        using var second = await client.SendAsync(Request(subject), TestContext.Current.CancellationToken);
        Assert.Equal(2, harness.Calls);
        Assert.Empty(harness.Origin.Received);
        Assert.All(harness.Logs, message =>
        {
            Assert.DoesNotContain(subject, message);
            Assert.DoesNotContain(result, message);
            Assert.DoesNotContain(string.Concat("synthetic-", "not-a-credential"), message);
        });
    }

    [Theory]
    [InlineData(400, 401)]
    [InlineData(401, 401)]
    [InlineData(302, 401)]
    [InlineData(429, 401)]
    [InlineData(503, 401)]
    public async Task should_never_fall_back_to_the_subject_after_identity_failure(int status, int expected)
    {
        await using var harness = new TokenExchangeHarness { Status = (HttpStatusCode)status };
        using var client = harness.CreateBearerClient();
        using var response = await client.SendAsync(Request(harness.Subject()), TestContext.Current.CancellationToken);
        Assert.Equal(expected, (int)response.StatusCode);
        Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData(true, HttpStatusCode.Unauthorized)]
    [InlineData(false, HttpStatusCode.Forbidden)]
    public async Task should_not_contact_identity_without_an_allowlisted_issuer_and_address(bool unknownIssuer, HttpStatusCode expected)
    {
        await using var harness = new TokenExchangeHarness();
        using var client = harness.CreateBearerClient();
        var token = unknownIssuer ? harness.Issuer.Token(new StubIssuer.TokenRequest { Issuer = "https://unknown.example" }) : harness.Subject();
        using var request = Request(token);
        if (!unknownIssuer) request.Headers.Host = "unmapped.example";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(0, harness.Calls);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_allow_direct_identity_tokens_without_exchange()
    {
        await using var harness = new TokenExchangeHarness();
        using var client = harness.CreateBearerClient();
        using var response = await client.SendAsync(Request(harness.Exchanged()), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, harness.Calls);
    }

    static HttpRequestMessage Request(string subject)
    {
        var request = BearerRouteHarness.WithToken(HttpMethod.Get, BearerRouteHarness.RoutePrefix, subject);
        request.Headers.Host = "a.direct.example.test";
        return request;
    }

    static string Hostile(TokenExchangeHarness harness, string hostile) => hostile switch
    {
        "resource-audience" => harness.Exchanged(audience: "https://cratis.direct/mcp"),
        "wrong-audience" => harness.Exchanged(audience: "other"),
        "wrong-tenant" => harness.Exchanged(tenant: "tenant-b"),
        "case-tenant" => harness.Exchanged(tenant: "TENANT-A"),
        "wrong-idp" => harness.Exchanged(idp: "https://other.example"),
        "missing-idp" => harness.Issuer.Token(new StubIssuer.TokenRequest { Audience = "direct-mcp", Without = ["idp"], Claims = RequiredClaims() }),
        "missing-tenant" or "several-tenants" or "unusable-tenant" or "tenant-id-only" => HostileTenant(harness, hostile),
        _ => InvalidToken(harness, hostile),
    };

    static string InvalidToken(TokenExchangeHarness harness, string hostile) => hostile switch
    {
        "wrong-issuer" => harness.Issuer.Token(new StubIssuer.TokenRequest { Issuer = "https://wrong.example" }),
        "bad-signature" => BadSignature(harness),
        "expired" => harness.Issuer.Token(new StubIssuer.TokenRequest { Audience = "direct-mcp", Expires = DateTime.UtcNow.AddMinutes(-10), Claims = RequiredClaims() }),
        "missing-scope" => harness.Exchanged(scope: "other"),
        "bound-token" => BoundToken(harness),
        _ => throw new InvalidOperationException("Unknown synthetic case."),
    };

    static string HostileTenant(TokenExchangeHarness harness, string hostile)
    {
        var claims = RequiredClaims();
        claims["idp"] = TokenExchangeHarness.ExternalIssuer;
        claims.Remove("tid");
        if (hostile == "tenant-id-only") claims["tenant_id"] = "tenant-a";
        else if (hostile != "missing-tenant") claims["tid"] = hostile == "several-tenants" ? new[] { "tenant-a", "tenant-b" } : "../tenant-a";
        return harness.Issuer.Token(new StubIssuer.TokenRequest { Audience = "direct-mcp", Without = ["tid"], Claims = claims });
    }

    static Dictionary<string, object> RequiredClaims() => new() { ["scope"] = "direct-mcp:read", ["env"] = "staging", ["tid"] = "tenant-a" };

    static string BoundToken(TokenExchangeHarness harness)
    {
        var claims = RequiredClaims();
        claims["idp"] = TokenExchangeHarness.ExternalIssuer;
        claims["cnf"] = new Dictionary<string, object> { ["jkt"] = "synthetic-proof-key" };
        return harness.Issuer.Token(new StubIssuer.TokenRequest { Audience = "direct-mcp", Claims = claims });
    }

    static string BadSignature(TokenExchangeHarness harness)
    {
        var parts = harness.Exchanged().Split('.');
        return $"{parts[0]}.{parts[1]}.{harness.Issuer.TokenSignedByAnotherKey().Split('.')[2]}";
    }
}
