// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>Verifies the normal cookie-session flow against final wire observations, not pre-transform state.</summary>
/// <param name="harness">The running v1 deployment.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_a_signed_session_reaches_the_backend(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    ForwardedIdentityObservation _observed = null!;
    ForwardedIdentityObservation _identity = null!;
    HttpStatusCode _status;

    public async ValueTask InitializeAsync()
    {
        harness.ApplicationOrigin.Received.Clear();
        using var client = harness.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/api/orders?x=1");
        request.Headers.Add("X-Cratis-Forwarded-Identity-Signature", "caller-proof");
        using var response = await client.SendAsync(request);
        _status = response.StatusCode;
        _observed = harness.ApplicationOrigin.Received.Last(observed => !observed.RawTarget.Contains(WellKnownPaths.IdentityDetails, StringComparison.Ordinal));
        _identity = harness.ApplicationOrigin.Received.Last(observed => observed.RawTarget.Contains(WellKnownPaths.IdentityDetails, StringComparison.Ordinal));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_reach_the_backend() => Assert.Equal(HttpStatusCode.OK, _status);
    [Fact] public void should_sign_the_final_base_path_and_request_target() => Assert.StartsWith("/base/api/orders?x=1", _observed.RawTarget, StringComparison.OrdinalIgnoreCase);
    [Fact] public void should_be_accepted_by_the_independent_verifier() => Assert.True(_observed.Verified);
    [Fact] public void should_also_sign_the_identity_details_call() => Assert.True(_identity.Verified);
    [Fact] public void should_sign_exactly_one_fresh_proof() => Assert.Single(_observed.Headers[Headers.ForwardedIdentitySignature]);
    [Fact] public void should_not_reuse_the_callers_proof() => Assert.NotEqual("caller-proof", _observed.Proof);
    [Fact] public void should_forward_the_routed_service() => Assert.Equal("app", _observed.Headers[Headers.ServiceId].Single());
    [Fact] public void should_use_the_selected_services_key() => Assert.StartsWith("v1.active-1.", _observed.Proof, StringComparison.Ordinal);

    [Theory]
    [InlineData("x-ms-client-principal")]
    [InlineData("x-ms-client-principal-id")]
    [InlineData("x-ms-client-principal-name")]
    [InlineData("x-ms-client-principal-name-ex")]
    [InlineData("x-cratis-tenant-id")]
    [InlineData("tenant-id")]
    [InlineData("x-cratis-microservice")]
    [InlineData("service-id")]
    public void should_reject_a_changed_covered_value(string name)
    {
        var headers = _observed.Headers.ToDictionary(header => header.Key, header => header.Value, StringComparer.OrdinalIgnoreCase);
        headers[name] = ["tampered"];
        Assert.False(Verify(_observed with { Headers = headers }));
    }

    [Fact] public void should_reject_a_changed_method() => Assert.False(Verify(_observed with { Method = "POST" }));
    [Fact] public void should_reject_a_changed_path() => Assert.False(Verify(_observed with { RawTarget = "/different" }));
    [Fact] public void should_reject_the_wrong_audience() => Assert.False(ForwardedIdentityVerifier.Verify(_observed, "other-audience", harness.ApplicationOrigin.KeyId, harness.ApplicationOrigin.Secret.ToArray()));
    [Fact] public void should_reject_the_wrong_key() => Assert.False(ForwardedIdentityVerifier.Verify(_observed, harness.ApplicationOrigin.Audience, harness.ApplicationOrigin.KeyId, harness.Other.Secret.ToArray()));
    [Fact] public void should_ignore_a_changed_query() => Assert.True(Verify(_observed with { RawTarget = _observed.RawTarget.Split('?')[0] + "?x=2" }));

    bool Verify(ForwardedIdentityObservation observation) => ForwardedIdentityVerifier.Verify(observation, harness.ApplicationOrigin.Audience, harness.ApplicationOrigin.KeyId, harness.ApplicationOrigin.Secret.ToArray());
}
