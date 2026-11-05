// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>Verifies direct-forwarder bearer signing after path construction and token-field injection.</summary>
/// <param name="harness">The running v1 deployment.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_a_signed_bearer_request_reaches_the_backend(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    ForwardedIdentityObservation _observed = null!;
    HttpStatusCode _status;
    public async ValueTask InitializeAsync()
    {
        harness.ApplicationOrigin.Received.Clear();
        using var client = harness.CreateSecurityClient();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Post, BearerRouteHarness.RoutePrefix + "/tools?x=1", harness.Issuer.Token());
        request.Headers.Host = ForwardedIdentityHarness.SignedHost;
        request.Headers.Add(Headers.ForwardedIdentitySignature, "forged");
        request.Headers.Add(Headers.ServiceId, "other");
        request.Headers.Add(Headers.LegacyServiceId, "other");
        using var response = await client.SendAsync(request);
        _status = response.StatusCode;
        _observed = harness.ApplicationOrigin.Received.Last();
    }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    [Fact] public void should_reach_the_backend() => Assert.Equal(HttpStatusCode.OK, _status);
    [Fact] public void should_bind_the_final_base_path() => Assert.StartsWith("/base/mcp/tools", _observed.RawTarget, StringComparison.Ordinal);
    [Fact] public void should_be_accepted_by_the_independent_verifier() => Assert.True(_observed.Verified);
    [Fact] public void should_replace_the_callers_service_selector() => Assert.Equal("app", _observed.Headers[Headers.ServiceId].Single());
    [Fact] public void should_replace_the_legacy_service_selector() => Assert.Equal("app", _observed.Headers[Headers.LegacyServiceId].Single());
    [Fact] public void should_cover_the_injected_client_id() => Assert.True(_observed.Headers.ContainsKey(Headers.TokenClientId));
    [Fact] public void should_cover_the_injected_scopes() => Assert.True(_observed.Headers.ContainsKey(Headers.TokenScope));
    [Fact] public void should_not_forward_the_bearer_token() => Assert.False(_observed.Headers.ContainsKey("Authorization"));
    [Theory]
    [InlineData("x-cratis-token-client-id")]
    [InlineData("x-cratis-token-scope")]
    public void should_reject_a_changed_token_field(string name)
    {
        var headers = _observed.Headers.ToDictionary(header => header.Key, header => header.Value, StringComparer.OrdinalIgnoreCase);
        headers[name] = ["tampered"];
        Assert.False(ForwardedIdentityVerifier.Verify(_observed with { Headers = headers }, harness.ApplicationOrigin.Audience, harness.ApplicationOrigin.KeyId, harness.ApplicationOrigin.Secret.ToArray()));
    }
}
