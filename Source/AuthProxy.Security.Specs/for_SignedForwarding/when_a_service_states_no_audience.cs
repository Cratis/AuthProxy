// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// A service that states no forwarding audience receives assertions for its configuration key, so an assertion one
/// service received cannot be replayed to a sibling that expects its own.
/// </summary>
/// <param name="harness">The running signing proxy and its origins.</param>
[Collection(SignedForwardingSpecCollection.Name)]
public class when_a_service_states_no_audience(SignedForwardingHarness harness) : IAsyncLifetime
{
    const string Path = "/api/dashboard";

    HttpResponseMessage? _response;
    ForwardedAssertion? _assertion;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();

        var request = SecurityHarness.Authenticated(HttpMethod.Get, Path, SecurityHarness.UniqueUser("signed-app"));
        request.Headers.Host = SignedForwardingHarness.AppHost;
        _response = await client.SendAsync(request);
        _assertion = ForwardedAssertion.From(harness.App.LastRequestTo(Path));
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_attach_an_assertion() => Assert.NotNull(_assertion);
    [Fact] public void should_verify_with_the_pinned_public_key() => Assert.True(_assertion!.VerifiesWith(harness.Key.PublicKeyPem));
    [Fact] public void should_be_for_the_service_key() => Assert.Equal("app", _assertion!.Claim("aud"));
    [Fact] public void should_not_reach_the_other_service() => Assert.False(harness.Reports.ReceivedAnythingFor(Path));
}
