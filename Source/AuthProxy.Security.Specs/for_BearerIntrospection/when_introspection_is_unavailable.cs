// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace Cratis.AuthProxy.Security.for_BearerIntrospection;

/// <summary>
/// A token that cannot be confirmed active is not treated as active. On an MCP route, and on any route that does not
/// say otherwise, a silent, failing, misauthenticated or nonsensical introspection endpoint refuses the request with
/// <c language="text">503</c> and never forwards it. A route that explicitly accepts local validation alone proceeds,
/// but never when the endpoint answers that the token is inactive. Nothing sensitive is logged along the way.
/// </summary>
/// <param name="harness">The running proxy, origin, issuer and introspection endpoint.</param>
[Collection(IntrospectionSpecCollection.Name)]
public class when_introspection_is_unavailable(IntrospectionHarness harness) : IAsyncLifetime
{
    const string McpPath = $"{IntrospectionHarness.MarkedRoute}/tools";
    const string AcceptingPath = $"{IntrospectionHarness.CachedRoute}/tools";

    readonly Dictionary<string, HttpResponseMessage> _responses = [];
    TimeSpan _hungFor;
    bool _forwardedWhileFailing;
    bool _acceptedFailureWasLogged;
    bool _loggedSensitiveValue;
    int _callsForRecoveredToken;
    HttpStatusCode _revokedOnAcceptingRoute;
    HttpStatusCode _afterRecovery;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        var token = harness.Issuer.Token();
        harness.Endpoint.Activate(token);

        foreach (var (name, status) in new[] { ("server_error", 500), ("throttled", 429), ("client_refused", 401), ("client_forbidden", 403), ("redirect", 302) })
        {
            harness.Endpoint.Reset();
            harness.Endpoint.FailWith = status;
            harness.Origin.Clear();
            _responses[name] = await Send(client, McpPath, token);
            _forwardedWhileFailing |= harness.Origin.ReceivedAnythingFor(McpPath);
        }

        harness.Endpoint.Reset();
        harness.Endpoint.RawBody = "<html>not json</html>";
        _responses["not_json"] = await Send(client, McpPath, token);

        harness.Endpoint.Reset();
        harness.Endpoint.RawBody = """{"active":"yes"}""";
        _responses["not_boolean"] = await Send(client, McpPath, token);

        harness.Endpoint.Reset();
        harness.Endpoint.Hang = true;
        var stopwatch = Stopwatch.StartNew();
        _responses["silent"] = await Send(client, McpPath, token);
        _hungFor = stopwatch.Elapsed;

        // An accepting route proceeds on local validation alone, with a warning, when the endpoint cannot be asked...
        harness.Endpoint.Reset();
        harness.Endpoint.FailWith = 503;
        _responses["accepted"] = await Send(client, AcceptingPath, token);
        _acceptedFailureWasLogged = harness.Logs.Mentioning("Accepted on local validation alone");

        // ...but a reachable endpoint reporting the token inactive always refuses, and nothing was cached by failing.
        harness.Endpoint.Reset();
        harness.Endpoint.Revoke(token);
        _revokedOnAcceptingRoute = (await Send(client, AcceptingPath, token)).StatusCode;

        harness.Endpoint.Reset();
        harness.Endpoint.Activate(token);
        _afterRecovery = (await Send(client, McpPath, token)).StatusCode;
        _callsForRecoveredToken = harness.Endpoint.CallsTo(StubIntrospectionEndpoint.Path);

        _loggedSensitiveValue = harness.Logs.Mentioning(token) || harness.Logs.Mentioning(StubIntrospectionEndpoint.ClientSecret);
    }

    public ValueTask DisposeAsync()
    {
        foreach (var response in _responses.Values)
        {
            response.Dispose();
        }

        return ValueTask.CompletedTask;
    }

    [Theory]
    [InlineData("server_error")]
    [InlineData("throttled")]
    [InlineData("client_refused")]
    [InlineData("client_forbidden")]
    [InlineData("redirect")]
    [InlineData("not_json")]
    [InlineData("not_boolean")]
    [InlineData("silent")]
    public void should_answer_service_unavailable(string failure) => Assert.Equal(HttpStatusCode.ServiceUnavailable, _responses[failure].StatusCode);

    [Theory]
    [InlineData("server_error")]
    [InlineData("silent")]
    public void should_ask_the_client_to_retry_later(string failure) => Assert.NotNull(_responses[failure].Headers.RetryAfter);

    [Theory]
    [InlineData("client_refused")]
    [InlineData("silent")]
    public void should_not_challenge_as_if_the_token_were_wrong(string failure) => Assert.Empty(_responses[failure].Headers.WwwAuthenticate);

    [Fact] public void should_not_forward_anything() => Assert.False(_forwardedWhileFailing);
    [Fact] public void should_give_up_on_a_silent_endpoint_at_the_timeout() => Assert.True(_hungFor < TimeSpan.FromSeconds(5), _hungFor.ToString());
    [Fact] public void should_proceed_on_a_route_that_accepts_local_validation_alone() => Assert.Equal(HttpStatusCode.OK, _responses["accepted"].StatusCode);
    [Fact] public void should_warn_when_it_does() => Assert.True(_acceptedFailureWasLogged);
    [Fact] public void should_still_refuse_a_token_reported_inactive_on_that_route() => Assert.Equal(HttpStatusCode.Unauthorized, _revokedOnAcceptingRoute);
    [Fact] public void should_recover_when_the_endpoint_does() => Assert.Equal(HttpStatusCode.OK, _afterRecovery);
    [Fact] public void should_not_have_cached_a_failure() => Assert.Equal(1, _callsForRecoveredToken);
    [Fact] public void should_not_log_the_token_or_the_client_secret() => Assert.False(_loggedSensitiveValue);

    static async Task<HttpResponseMessage> Send(HttpClient client, string path, string token) =>
        await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, path, token));
}
