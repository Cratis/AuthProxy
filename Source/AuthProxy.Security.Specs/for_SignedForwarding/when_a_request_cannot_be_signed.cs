// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// Once signing is configured, a request AuthProxy cannot sign is answered with <c language="text">502</c> and never
/// reaches the service unsigned, whether it is the proxied request or the identity call made on its behalf.
/// </summary>
/// <param name="harness">The running proxy whose signer fails, and its origin.</param>
[Collection(UnsignableForwardingSpecCollection.Name)]
public class when_a_request_cannot_be_signed(UnsignableForwardingHarness harness) : IAsyncLifetime
{
    const string Path = "/api/unsignable";

    HttpResponseMessage? _response;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(SecurityHarness.Authenticated(HttpMethod.Get, Path, SecurityHarness.UniqueUser("unsignable")));
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_answer_bad_gateway() => Assert.Equal(HttpStatusCode.BadGateway, _response!.StatusCode);
    [Fact] public void should_not_forward_the_request() => Assert.False(harness.Origin.ReceivedAnythingFor(Path));
    [Fact] public void should_not_call_the_identity_endpoint() => Assert.False(harness.Origin.ReceivedAnythingFor(WellKnownPaths.IdentityDetails));
}
