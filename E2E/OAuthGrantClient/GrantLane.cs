// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace E2E.OAuthGrantClient;

sealed class GrantLane : IDisposable
{
    readonly HttpClient _http = new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false }) { Timeout = TimeSpan.FromSeconds(10) };
    const string Proxy = "http://authproxy:8080";
    const string Issuer = "https://issuer:8443";
    const string Receiver = "http://receiver:8080";

    sealed record Scenario(
        string Name,
        string Token,
        string Path = "/grants/rest",
        bool Cookie = false,
        bool Poison = false,
        HttpStatusCode Expected = HttpStatusCode.Unauthorized,
        string McpMethod = "tools/call");

    public async Task Run()
    {
        using (var metadataRequest = new HttpRequestMessage(HttpMethod.Get, $"{Proxy}/.well-known/oauth-protected-resource/mcp"))
        {
            metadataRequest.Headers.Host = "grant.local";
            using var metadataResponse = await _http.SendAsync(metadataRequest);
            Require(metadataResponse.StatusCode == HttpStatusCode.OK, $"MCP resource metadata: HTTP {(int)metadataResponse.StatusCode}");
            Console.WriteLine("PASS: MCP resource metadata");
        }
        var person = await Mint("person");
        await Accept(new("REST person evidence", person));
        await McpList(new("MCP tools/list", person, "/mcp", McpMethod: "tools/list"));
        await Accept(new("MCP tools/call person evidence", person, "/mcp"));
        await Accept(new("caller-supplied identity/context is stripped", person, Poison: true));
        await Reject(new("bound token", await Mint("bound")));
        await Reject(new("unverified actor claims", await Mint("actor")));
        await Reject(new("wrong audience", await Mint("wrong-audience")));
        await Reject(new("wrong issuer", await Mint("wrong-issuer")));
        await Reject(new("wrong token type", await Mint("wrong-type")));
        await Reject(new("expired token", await Mint("expired")));
        await Reject(new("missing scope", await Mint("wrong-scope"), Expected: HttpStatusCode.Forbidden));
        var pat = $"direct_pat_v1_{new string('a', 64)}";
        var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pat)))[..8].ToLowerInvariant();
        await Reject(new("canonical-shaped PAT on OAuth-only route", $"{pat}_{checksum}"));
        await Reject(new("cookie plus bearer is ambiguous", person, Cookie: true, Expected: HttpStatusCode.BadRequest));
        await ClientCredentials();
        await Hostile();
        await Revocation();
        await Outage();
    }

    async Task<string> Mint(string scenario)
    {
        using var response = await _http.PostAsync($"{Issuer}/mint/{scenario}", null);
        response.EnsureSuccessStatusCode();
        using var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        return json.RootElement.GetProperty("access_token").GetString()!;
    }

    async Task Accept(Scenario scenario)
    {
        var name = scenario.Name;
        var before = await Count();
        using var response = await Send(scenario);
        var after = await Count();
        Require(response.StatusCode == HttpStatusCode.OK, $"{name}: HTTP {(int)response.StatusCode}, receiver ingress {after - before}");
        Require(after == before + 1, $"{name}: receiver ingress");
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        using var evidence = scenario.Path == "/mcp"
            ? JsonDocument.Parse(body.RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString()!)
            : JsonDocument.Parse(body.RootElement.GetRawText());
        var grant = evidence.RootElement;
        Require(grant.GetProperty("admitted").GetBoolean() && grant.GetProperty("kind").GetString() == "oauth-grant", name);
        Require(grant.GetProperty("credentialId").GetString() == "00000000-0000-4000-8000-000000000348" && grant.GetProperty("hashMatch").GetBoolean(), name);
        Require(grant.GetProperty("issuer").GetString() == Issuer && grant.GetProperty("subject").GetString() == "00000000-0000-4000-8000-000000000347", name);
        Console.WriteLine($"PASS: {name}");
    }

    async Task McpList(Scenario scenario)
    {
        var before = await Count();
        using var response = await Send(scenario);
        Require(response.StatusCode == HttpStatusCode.OK && await Count() == before + 1, "MCP tools/list");
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Require(body.RootElement.GetProperty("result").GetProperty("tools")[0].GetProperty("name").GetString() == "read_grant", "MCP tools/list");
        Console.WriteLine("PASS: MCP tools/list");
    }

    async Task Reject(Scenario scenario)
    {
        var before = await Count();
        using var response = await Send(scenario);
        Require(response.StatusCode == scenario.Expected && await Count() == before, scenario.Name);
        Console.WriteLine($"PASS: {scenario.Name}; receiver not reached");
    }

    async Task ClientCredentials()
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["service"] = "arc",
            ["client_id"] = "e2e-client",
            ["client_secret"] = "e2e-throwaway-secret"
        });
        using var response = await _http.PostAsync($"{Proxy}/.cratis/token", form);
        response.EnsureSuccessStatusCode();
        using var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        await Reject(new("locally issued client-credentials token", json.RootElement.GetProperty("access_token").GetString()!));
    }

    async Task Hostile()
    {
        using var response = await _http.PostAsJsonAsync($"{Receiver}/test/hostile", new { token = await Mint("person") });
        response.EnsureSuccessStatusCode();
        var checks = await response.Content.ReadFromJsonAsync<string[]>() ?? [];
        Require(checks.Length == 9, "hostile checks did not all execute");
        foreach (var check in checks) Console.WriteLine($"PASS: receiver rejects {check}");
    }

    async Task Revocation()
    {
        var token = await Mint("person");
        var scenario = new Scenario("active grant before revocation", token);
        await Accept(scenario);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token });
        using var revoked = await _http.PostAsync($"{Issuer}/revoke", form);
        revoked.EnsureSuccessStatusCode();
        var clock = Stopwatch.StartNew();
        while (true)
        {
            var before = await Count();
            using var response = await Send(scenario);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                Require(await Count() == before, "revoked token reached receiver");
                break;
            }
            Require(response.StatusCode == HttpStatusCode.OK && clock.Elapsed < TimeSpan.FromSeconds(3), "revocation exceeded two-second cache bound plus one-second scheduling allowance");
            await Task.Delay(50);
        }
        await Reject(new("revoked grant remains refused", token));
        Console.WriteLine("PASS: revocation observed within configured cache bound plus scheduling allowance");
    }

    async Task Outage()
    {
        var token = await Mint("person");
        using var enabled = await _http.PostAsync($"{Issuer}/outage/true", null);
        enabled.EnsureSuccessStatusCode();
        try { await Reject(new("introspection outage fails closed", token, Expected: HttpStatusCode.ServiceUnavailable)); }
        finally
        {
            using var disabled = await _http.PostAsync($"{Issuer}/outage/false", null);
            disabled.EnsureSuccessStatusCode();
        }
    }

    Task<int> Count() => _http.GetFromJsonAsync<int>($"{Receiver}/test/count");

    Task<HttpResponseMessage> Send(Scenario scenario)
    {
        var request = new HttpRequestMessage(scenario.Path.EndsWith("mcp", StringComparison.Ordinal) ? HttpMethod.Post : HttpMethod.Get, $"{Proxy}{scenario.Path}");
        if (scenario.Path == "/mcp") request.Content = JsonContent.Create(new { jsonrpc = "2.0", id = 1, method = scenario.McpMethod, @params = new { name = "read_grant", arguments = new { } } });
        request.Headers.Host = "grant.local";
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", scenario.Token);
        if (scenario.Cookie) request.Headers.Add("Cookie", ".Cratis.AuthProxy.Auth.v2=e2e-cookie-marker");
        if (scenario.Poison)
        {
            foreach (var name in new[] { "principal", "principal-id", "principal-name", "principal-idp" }) request.Headers.TryAddWithoutValidation($"x-ms-client-{name}", "untrusted");
            foreach (var name in new[] { "credential-kind", "credential-id", "issuer", "subject", "idp", "auth-time", "acr", "amr", "act", "grant-id", "policy-epoch", "sender-binding", "forwarded-token-sha256", "forwarded-identity-signature", "tenant-id", "token-client-id", "token-scope" }) request.Headers.TryAddWithoutValidation($"x-cratis-{name}", "untrusted");
        }
        return SendAndDispose(request);
    }

    async Task<HttpResponseMessage> SendAndDispose(HttpRequestMessage request)
    {
        using (request) return await _http.SendAsync(request);
    }

    static void Require(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException($"FAIL: {name}");
    }

    public void Dispose() => _http.Dispose();
}
