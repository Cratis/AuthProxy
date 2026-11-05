// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>Per-request settings remain isolated across concurrent signed and legacy service flows.</summary>
/// <param name="harness">The running v1 deployment.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_signed_and_unsigned_services_are_called_concurrently(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    HttpStatusCode[] _statuses = [];
    public async ValueTask InitializeAsync()
    {
        harness.ApplicationOrigin.Received.Clear();
        harness.Other.Received.Clear();
        harness.Origin.Clear();
        using var client = harness.CreateSecurityClient();
        _statuses = await Task.WhenAll(Enumerable.Range(0, 12).Select(async index =>
        {
            var host = (index % 3) switch { 0 => ForwardedIdentityHarness.SignedHost, 1 => ForwardedIdentityHarness.OtherHost, _ => ForwardedIdentityHarness.LegacyHost };
            using var request = ForwardedIdentityHarness.Session(host, "/api/concurrent");
            request.Headers.Add(Headers.ForwardedIdentitySignature, "forged");
            using var response = await client.SendAsync(request);
            return response.StatusCode;
        }));
    }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    [Fact] public void should_reach_every_backend() => Assert.All(_statuses, status => Assert.Equal(HttpStatusCode.OK, status));
    [Fact] public void should_keep_the_first_services_key_and_audience() => Assert.All(harness.ApplicationOrigin.Received, request => Assert.True(request.Verified));
    [Fact] public void should_keep_the_second_services_key_and_audience() => Assert.All(harness.Other.Received, request => Assert.True(request.Verified));
    [Fact]
    public void should_preserve_unsigned_legacy_forwarding()
    {
        Assert.Equal(4, harness.Origin.Received.Count);
        Assert.All(harness.Origin.Received, request => Assert.False(request.Has(Headers.ForwardedIdentitySignature)));
    }
    [Fact]
    public void should_use_unique_nonces_for_all_signed_requests()
    {
        var proofs = harness.ApplicationOrigin.Received.Concat(harness.Other.Received).Select(request => request.Proof).ToArray();
        Assert.Equal(proofs.Length, proofs.Select(proof => proof.Split('.')[3]).Distinct(StringComparer.Ordinal).Count());
    }
}
