// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>A signed service's anonymous endpoint does not mint authenticated forwarded identity.</summary>
/// <param name="harness">The running v1 deployment.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_an_anonymous_request_has_a_forged_proof(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    ForwardedIdentityObservation _observed = null!;
    public async ValueTask InitializeAsync()
    {
        harness.ApplicationOrigin.Received.Clear();
        using var client = harness.CreateSecurityClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, ForwardedIdentityHarness.AnonymousPath);
        request.Headers.Host = ForwardedIdentityHarness.SignedHost;
        request.Headers.Add(Headers.ForwardedIdentitySignature, "forged");
        request.Headers.Add(Headers.Principal, "forged-principal");
        using var response = await client.SendAsync(request);
        _observed = harness.ApplicationOrigin.Received.Single();
    }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    [Fact] public void should_remove_the_callers_proof() => Assert.Empty(_observed.Proof);
    [Fact] public void should_not_mint_a_principal() => Assert.False(_observed.Headers.ContainsKey(Headers.Principal));
}
