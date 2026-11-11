// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerIntrospection;

/// <summary>
/// The identity provider sees the token it issued and AuthProxy's own client credential, and nothing else: no
/// cookie, no caller headers, no query, no request data. A token that fails local validation is never sent to it,
/// and an active answer is reused only on a route that opted into caching.
/// </summary>
/// <param name="harness">The running proxy, origin, issuer and introspection endpoint.</param>
[Collection(IntrospectionSpecCollection.Name)]
public class when_introspection_is_asked(IntrospectionHarness harness) : IAsyncLifetime
{
    const string McpPath = $"{IntrospectionHarness.MarkedRoute}/tools";
    const string CachedPath = $"{IntrospectionHarness.CachedRoute}/tools";

    CapturedIntrospection? _call;
    string _token = string.Empty;
    int _callsForForeignToken;
    int _callsForExpiredToken;
    int _callsForNoToken;
    int _callsForCachedRoute;
    int _callsForUncachedRoute;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Endpoint.Reset();

        _token = harness.Issuer.Token();
        harness.Endpoint.Activate(_token);
        var request = BearerRouteHarness.WithToken(HttpMethod.Post, $"{McpPath}?token=in-the-url", _token);
        request.Headers.TryAddWithoutValidation("Cookie", ".cratis-session=some-session");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.9");
        request.Headers.TryAddWithoutValidation("X-Tenant-Id", "spoofed");
        (await client.SendAsync(request)).Dispose();
        _call = harness.Endpoint.Captured.FirstOrDefault();

        harness.Endpoint.Reset();
        (await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, McpPath, harness.Issuer.TokenSignedByAnotherKey()))).Dispose();
        _callsForForeignToken = harness.Endpoint.Captured.Count;

        (await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, McpPath, harness.Issuer.Token(new StubIssuer.TokenRequest { Expires = DateTime.UtcNow.AddHours(-1) })))).Dispose();
        _callsForExpiredToken = harness.Endpoint.Captured.Count;

        (await client.GetAsync(McpPath)).Dispose();
        _callsForNoToken = harness.Endpoint.Captured.Count;

        harness.Endpoint.Reset();
        var cached = harness.Issuer.Token();
        harness.Endpoint.Activate(cached);
        for (var i = 0; i < 3; i++)
        {
            (await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, CachedPath, cached))).Dispose();
            (await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, McpPath, cached))).Dispose();
        }

        _callsForCachedRoute = harness.Endpoint.CallsTo(StubIntrospectionEndpoint.CachedPath);
        _callsForUncachedRoute = harness.Endpoint.CallsTo(StubIntrospectionEndpoint.Path);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_post() => Assert.Equal("POST", _call!.Method);
    [Fact] public void should_send_a_form() => Assert.StartsWith("application/x-www-form-urlencoded", _call!.ContentType);
    [Fact] public void should_send_only_the_token_and_its_hint() => Assert.Equal(["token", "token_type_hint"], _call!.FormFields);
    [Fact] public void should_send_the_token() => Assert.Equal(_token, _call!.Token);
    [Fact] public void should_authenticate_as_the_configured_client() => Assert.Equal("Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{StubIntrospectionEndpoint.ClientId}:{StubIntrospectionEndpoint.ClientSecret}")), _call!.Authorization);
    [Fact] public void should_not_put_anything_in_the_url() => Assert.Empty(_call!.Query);
    [Fact] public void should_not_send_the_cookie() => Assert.DoesNotContain("Cookie", _call!.HeaderNames, StringComparer.OrdinalIgnoreCase);
    [Fact] public void should_not_send_forwarding_headers() => Assert.DoesNotContain(_call!.HeaderNames, _ => _.StartsWith("X-", StringComparison.OrdinalIgnoreCase));
    [Fact] public void should_not_ask_about_a_token_signed_by_another_key() => Assert.Equal(0, _callsForForeignToken);
    [Fact] public void should_not_ask_about_an_expired_token() => Assert.Equal(0, _callsForExpiredToken);
    [Fact] public void should_not_ask_when_there_is_no_token() => Assert.Equal(0, _callsForNoToken);
    [Fact] public void should_reuse_an_active_answer_on_a_route_that_caches() => Assert.Equal(1, _callsForCachedRoute);
    [Fact] public void should_ask_every_time_on_a_route_that_does_not_cache() => Assert.Equal(3, _callsForUncachedRoute);
}
