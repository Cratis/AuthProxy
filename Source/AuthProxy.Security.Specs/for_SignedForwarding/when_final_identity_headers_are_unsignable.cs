// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>Configured signing never silently downgrades an unsignable identity-bearing outbound request.</summary>
/// <param name="harness">The running v1 deployment.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_final_identity_headers_are_unsignable(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    HttpStatusCode _status;
    public async ValueTask InitializeAsync()
    {
        harness.ApplicationOrigin.Received.Clear();
        using var client = harness.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, ForwardedIdentityHarness.RefusedPath);
        using var response = await client.SendAsync(request);
        _status = response.StatusCode;
    }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    [Fact] public void should_return_a_generic_gateway_failure() => Assert.Equal(HttpStatusCode.BadGateway, _status);
    [Fact] public void should_not_send_the_unprovable_request() => Assert.DoesNotContain(harness.ApplicationOrigin.Received, request => request.RawTarget.Contains(ForwardedIdentityHarness.RefusedPath, StringComparison.Ordinal));
}
