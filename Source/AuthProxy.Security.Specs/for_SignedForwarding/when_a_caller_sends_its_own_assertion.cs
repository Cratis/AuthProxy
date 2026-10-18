// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// An assertion the caller wrote never reaches a service: the one that arrives is the one AuthProxy signed.
/// </summary>
/// <param name="harness">The running signing proxy and its origins.</param>
[Collection(SignedForwardingSpecCollection.Name)]
public class when_a_caller_sends_its_own_assertion(SignedForwardingHarness harness) : IAsyncLifetime
{
    const string Forged = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.forged";

    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();

        var request = SecurityHarness.Authenticated(HttpMethod.Get, $"{SignedForwardingHarness.ReportsPrefix}/api/spoofed", SecurityHarness.UniqueUser("signed-spoof"));
        request.Headers.TryAddWithoutValidation(Headers.ForwardedIdentity, Forged);
        _response = await client.SendAsync(request);
        _forwarded = harness.Reports.LastRequestTo("/api/spoofed");
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.NotNull(_forwarded);
    [Fact] public void should_not_forward_the_callers_assertion() => Assert.DoesNotContain(Forged, _forwarded!.Value(Headers.ForwardedIdentity), StringComparison.Ordinal);
    [Fact] public void should_forward_an_assertion_that_verifies() => Assert.True(ForwardedAssertion.From(_forwarded)!.VerifiesWith(harness.Key.PublicKeyPem));
}
