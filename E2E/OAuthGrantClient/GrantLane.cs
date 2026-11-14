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
        await Accept("REST person evidence", person, "/grants/rest");
        await McpList(person);
        await Accept("MCP tools/call person evidence", person, "/mcp");
        await Accept("caller-supplied identity/context is stripped", person, "/grants/rest", poison: true);
        await Reject("bound token", await Mint("bound"));
        await Reject("unverified actor claims", await Mint("actor"));
        await Reject("wrong audience", await Mint("wrong-audience"));
        await Reject("wrong issuer", await Mint("wrong-issuer"));
        await Reject("wrong token type", await Mint("wrong-type"));
        await Reject("expired token", await Mint("expired"));
        await Reject("missing scope", await Mint("wrong-scope"), expected: HttpStatusCode.Forbidden);
        var pat = $"direct_pat_v1_{new string('a', 64)}";
        var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pat)))[..8].ToLowerInvariant();
        await Reject("canonical-shaped PAT on OAuth-only route", $"{pat}_{checksum}");
        await Reject("cookie plus bearer is ambiguous", person, cookie: true, expected: HttpStatusCode.BadRequest);
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

    async Task Accept(string name, string token, string path, bool poison = false)
    {
        var before = await Count();
        using var response = await Send(token, path, poison: poison);
        var after = await Count();
        Require(response.StatusCode == HttpStatusCode.OK, $"{name}: HTTP {(int)response.StatusCode}, receiver ingress {after - before}");
        Require(after == before + 1, $"{name}: receiver ingress");
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        using var evidence = path == "/mcp"
            ? JsonDocument.Parse(body.RootElement.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString()!)
            : JsonDocument.Parse(body.RootElement.GetRawText());
        var grant = evidence.RootElement;
        Require(grant.GetProperty("admitted").GetBoolean() && grant.GetProperty("kind").GetString() == "oauth-grant", name);
        Require(grant.GetProperty("credentialId").GetString() == "00000000-0000-4000-8000-000000000348" && grant.GetProperty("hashMatch").GetBoolean(), name);
        Require(grant.GetProperty("issuer").GetString() == Issuer && grant.GetProperty("subject").GetString() == "00000000-0000-4000-8000-000000000347", name);
        Console.WriteLine($"PASS: {name}");
    }

    async Task McpList(string token)
    {
        var before = await Count();
        using var response = await Send(token, "/mcp", mcpMethod: "tools/list");
        Require(response.StatusCode == HttpStatusCode.OK && await Count() == before + 1, "MCP tools/list");
        using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Require(body.RootElement.GetProperty("result").GetProperty("tools")[0].GetProperty("name").GetString() == "read_grant", "MCP tools/list");
        Console.WriteLine("PASS: MCP tools/list");
    }

    async Task Reject(string name, string token, bool cookie = false, HttpStatusCode expected = HttpStatusCode.Unauthorized)
    {
        var before = await Count();
        using var response = await Send(token, "/grants/rest", cookie: cookie);
        Require(response.StatusCode == expected && await Count() == before, name);
        Console.WriteLine($"PASS: {name}; receiver not reached");
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
        await Reject("locally issued client-credentials token", json.RootElement.GetProperty("access_token").GetString()!);
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
        await Accept("active grant before revocation", token, "/grants/rest");
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token });
        using var revoked = await _http.PostAsync($"{Issuer}/revoke", form);
        revoked.EnsureSuccessStatusCode();
        var clock = Stopwatch.StartNew();
        while (true)
        {
            var before = await Count();
            using var response = await Send(token, "/grants/rest");
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                Require(await Count() == before, "revoked token reached receiver");
                break;
            }
            Require(response.StatusCode == HttpStatusCode.OK && clock.Elapsed < TimeSpan.FromSeconds(3), "revocation exceeded two-second cache bound plus one-second scheduling allowance");
            await Task.Delay(50);
        }
        await Reject("revoked grant remains refused", token);
        Console.WriteLine("PASS: revocation observed within configured cache bound plus scheduling allowance");
    }

    async Task Outage()
    {
        var token = await Mint("person");
        using var enabled = await _http.PostAsync($"{Issuer}/outage/true", null);
        enabled.EnsureSuccessStatusCode();
        try { await Reject("introspection outage fails closed", token, expected: HttpStatusCode.ServiceUnavailable); }
        finally
        {
            using var disabled = await _http.PostAsync($"{Issuer}/outage/false", null);
            disabled.EnsureSuccessStatusCode();
        }
    }

    Task<int> Count() => _http.GetFromJsonAsync<int>($"{Receiver}/test/count");

    Task<HttpResponseMessage> Send(string token, string path, bool cookie = false, bool poison = false, string mcpMethod = "tools/call")
    {
        var request = new HttpRequestMessage(path.EndsWith("mcp", StringComparison.Ordinal) ? HttpMethod.Post : HttpMethod.Get, $"{Proxy}{path}");
        if (path == "/mcp") request.Content = JsonContent.Create(new { jsonrpc = "2.0", id = 1, method = mcpMethod, @params = new { name = "read_grant", arguments = new { } } });
        request.Headers.Host = "grant.local";
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (cookie) request.Headers.Add("Cookie", ".Cratis.AuthProxy.Auth.v2=e2e-cookie-marker");
        if (poison)
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
