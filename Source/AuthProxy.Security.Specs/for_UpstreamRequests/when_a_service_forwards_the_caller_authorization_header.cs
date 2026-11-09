// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_UpstreamRequests;

/// <summary>
/// Forwarding configuration does not permit a bearer token accompanied by the authentication cookie.
/// </summary>
/// <param name="harness">The running proxy and its origins.</param>
[Collection(UpstreamRequestsSpecCollection.Name)]
public class when_a_service_forwards_the_caller_authorization_header(UpstreamRequestsHarness harness) : IAsyncLifetime
{
    HttpStatusCode _status;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        using var request = UpstreamRequestsHarness.Request(UpstreamRequestsHarness.ForwardingHost, "/api/orders", true);
        using var response = await client.SendAsync(request);
        _status = response.StatusCode;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_refuse_mixed_authentication() => Assert.Equal(HttpStatusCode.Unauthorized, _status);

    [Fact]
    public void should_not_contact_the_service() => Assert.False(harness.Forwarding.ReceivedAnythingFor("/api/orders"));
}
