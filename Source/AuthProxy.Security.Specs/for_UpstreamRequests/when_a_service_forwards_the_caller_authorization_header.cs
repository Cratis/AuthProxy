// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_UpstreamRequests;

/// <summary>
/// A service configured to forward the caller's Authorization header receives it on a session request.
/// </summary>
/// <param name="harness">The running proxy and its origins.</param>
[Collection(UpstreamRequestsSpecCollection.Name)]
public class when_a_service_forwards_the_caller_authorization_header(UpstreamRequestsHarness harness) : IAsyncLifetime
{
    ForwardedRequest? _received;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        await client.SendAsync(UpstreamRequestsHarness.Request(UpstreamRequestsHarness.ForwardingHost, "/api/orders", true));
        _received = harness.Forwarding.LastRequestTo("/api/orders");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_forward_the_authorization_header() => Assert.Equal("Bearer callers-own-token", _received!.Value("Authorization"));

    [Fact]
    public void should_forward_only_the_application_cookie() => Assert.Equal("theme=dark", _received!.Value("Cookie"));
}
