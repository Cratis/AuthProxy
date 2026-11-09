// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json.Nodes;

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// The signature covers the forwarded principal, and with it every claim in it: a claim added or changed after
/// signing, such as an authentication time, invalidates the proof.
/// </summary>
/// <param name="harness">The running v1 deployment.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_an_authentication_time_claim_is_added_to_a_signed_principal(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    ForwardedIdentityObservation _observed = null!;

    public async ValueTask InitializeAsync()
    {
        harness.ApplicationOrigin.Received.Clear();
        using var client = harness.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/api/orders");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        _observed = harness.ApplicationOrigin.Received.Last(observed => !observed.RawTarget.Contains(WellKnownPaths.IdentityDetails, StringComparison.Ordinal));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_verify_the_untouched_principal() => Assert.True(Verify(_observed));
    [Fact] public void should_reject_an_added_authentication_time() => Assert.False(Verify(WithClaim("1700000000")));
    [Fact] public void should_reject_a_later_authentication_time() => Assert.False(Verify(WithClaim("9999999999")));

    ForwardedIdentityObservation WithClaim(string value)
    {
        var principal = JsonNode.Parse(Convert.FromBase64String(_observed.Headers[Headers.Principal].Single()))!.AsObject();
        var claims = principal["claims"] as JsonArray ?? [];
        claims.Add(new JsonObject { ["type"] = "auth_time", ["value"] = value });
        principal["claims"] = claims;
        var headers = _observed.Headers.ToDictionary(header => header.Key, header => header.Value, StringComparer.OrdinalIgnoreCase);
        headers[Headers.Principal] = [Convert.ToBase64String(Encoding.UTF8.GetBytes(principal.ToJsonString()))];
        return _observed with { Headers = headers };
    }

    bool Verify(ForwardedIdentityObservation observation) => ForwardedIdentityVerifier.Verify(observation, harness.ApplicationOrigin.Audience, harness.ApplicationOrigin.KeyId, harness.ApplicationOrigin.Secret.ToArray());
}
