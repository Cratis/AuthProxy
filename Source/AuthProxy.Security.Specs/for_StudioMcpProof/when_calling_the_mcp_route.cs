// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Security.for_StudioMcpProof.given;

namespace Cratis.AuthProxy.Security.for_StudioMcpProof;

// Throwaway local proof: never committed upstream.
[Collection(StudioMcpProofCollection.Name)]
public class when_calling_the_mcp_route(StudioMcpProxy proxy)
{
    const string ExpectedMetadata = $"resource_metadata=\"{StudioMcpProxy.ResourceMetadataUrl}\"";

    [Fact]
    public async Task case_1_a_minted_client_credentials_token_is_accepted()
    {
        using var client = proxy.CreateMachineClient();
        proxy.Origin.Clear();
        var (mintStatus, token) = await proxy.Mint(client);
        using var response = await client.SendAsync(StudioMcpProxy.McpCall(token));

        Observations.Record("with-route", "case 1 minted token", mintStatus, response, proxy.Origin.ReceivedAnythingFor("/mcp"), proxy.Verifier.LastUri);
        Assert.Equal(HttpStatusCode.OK, mintStatus);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(proxy.Origin.ReceivedAnythingFor("/mcp"));
    }

    [Fact]
    public async Task case_2_an_external_issuer_token_is_accepted()
    {
        using var client = proxy.CreateMachineClient();
        proxy.Origin.Clear();
        using var response = await client.SendAsync(StudioMcpProxy.McpCall(proxy.ExternalToken()));

        Observations.Record("with-route", $"case 2 external token (iss {proxy.Issuer.Issuer})", null, response, proxy.Origin.ReceivedAnythingFor("/mcp"), null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(proxy.Origin.ReceivedAnythingFor("/mcp"));
    }

    [Fact] public Task case_3_a_wrong_issuer_is_refused() => Refused("case 3 wrong issuer", proxy.ExternalToken(issuer: "https://other-issuer.local.test/"));

    [Fact] public Task case_3_the_issuer_without_its_trailing_slash_is_refused() => Refused("case 3 issuer without trailing slash", proxy.ExternalToken(issuer: proxy.Issuer.Issuer.TrimEnd('/')));

    [Fact]
    public Task case_3_a_tampered_signature_is_refused()
    {
        var token = proxy.ExternalToken();
        var last = token[^2];
        var tampered = string.Concat(token.AsSpan(0, token.Length - 2), last == 'A' ? "B" : "A", token.AsSpan(token.Length - 1));
        return Refused("case 3 tampered signature", tampered);
    }

    [Fact] public Task case_3_a_missing_scope_is_refused() => Refused("case 3 missing scope", proxy.ExternalToken(new Dictionary<string, object> { ["scope"] = "studio:other" }));

    [Fact] public Task case_3_an_unauthenticated_request_is_challenged() => Refused("case 3 unauthenticated", null);

    async Task Refused(string name, string? token)
    {
        using var client = proxy.CreateMachineClient();
        proxy.Origin.Clear();
        using var response = await client.SendAsync(StudioMcpProxy.McpCall(token));

        var forwarded = proxy.Origin.ReceivedAnythingFor("/mcp");
        Observations.Record("with-route", name, null, response, forwarded, null);
        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden, $"{name}: {response.StatusCode}");
        Assert.False(forwarded);
        var challenges = response.Headers.WwwAuthenticate.ToArray();
        Assert.Single(challenges);
        Assert.Equal("Bearer", challenges[0].Scheme);
        Assert.Contains(ExpectedMetadata, challenges[0].ToString(), StringComparison.Ordinal);
        Assert.Single(response.Headers.GetValues("WWW-Authenticate"));
    }
}

[Collection(StudioMcpProofCollection.Name)]
public class when_calling_the_mcp_route_without_the_issuer_configured(StudioMcpProxyWithoutIssuer proxy)
{
    [Fact]
    public void case_4_no_bearer_route_is_configured() =>
        Assert.DoesNotContain(proxy.AppliedSettings.Keys, key => key.Contains("BearerRoutes", StringComparison.Ordinal));

    [Fact]
    public async Task case_4_a_minted_client_credentials_token_is_still_accepted()
    {
        using var client = proxy.CreateMachineClient();
        proxy.Origin.Clear();
        var (mintStatus, token) = await proxy.Mint(client);
        using var response = await client.SendAsync(StudioMcpProxy.McpCall(token));

        Observations.Record("without-route", "case 4 minted token", mintStatus, response, proxy.Origin.ReceivedAnythingFor("/mcp"), proxy.Verifier.LastUri);
        Assert.Equal(HttpStatusCode.OK, mintStatus);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(proxy.Origin.ReceivedAnythingFor("/mcp"));
    }

    [Fact]
    public async Task case_4_an_external_issuer_token_is_refused()
    {
        using var client = proxy.CreateMachineClient();
        proxy.Origin.Clear();
        using var response = await client.SendAsync(StudioMcpProxy.McpCall(proxy.ExternalToken()));

        var forwarded = proxy.Origin.ReceivedAnythingFor("/mcp");
        Observations.Record("without-route", "case 4 external token", null, response, forwarded, null);
        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden, response.StatusCode.ToString());
        Assert.False(forwarded);
    }

    [Fact]
    public async Task case_4_observe_unauthenticated()
    {
        using var client = proxy.CreateMachineClient();
        proxy.Origin.Clear();
        using var response = await client.SendAsync(StudioMcpProxy.McpCall(null));

        var forwarded = proxy.Origin.ReceivedAnythingFor("/mcp");
        Observations.Record("without-route", "case 4 unauthenticated (observation only)", null, response, forwarded, null);
        Assert.False(forwarded);
    }
}

static class Observations
{
    static readonly Lock _lock = new();

    public static void Record(string fixture, string name, HttpStatusCode? mintStatus, HttpResponseMessage response, bool forwarded, Uri? verifierUri)
    {
        var path = Environment.GetEnvironmentVariable("PROOF_OBSERVATIONS");
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        var challenges = response.Headers.TryGetValues("WWW-Authenticate", out var values) ? values.ToArray() : [];
        var line = $"[{fixture}] {name}: mint={(mintStatus is null ? "-" : ((int)mintStatus).ToString(System.Globalization.CultureInfo.InvariantCulture))} " +
            $"status={(int)response.StatusCode} forwarded={forwarded} verifier={verifierUri?.AbsoluteUri ?? "-"} " +
            $"www-authenticate-count={challenges.Length} www-authenticate=[{string.Join(" | ", challenges)}]";
        lock (_lock)
        {
            File.AppendAllText(path, line + Environment.NewLine);
        }
    }
}
