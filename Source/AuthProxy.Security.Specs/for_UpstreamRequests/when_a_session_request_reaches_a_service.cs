// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_UpstreamRequests;

/// <summary>
/// What a service receives from a signed-in session: the application's own cookies, but neither AuthProxy's cookies nor the caller's own Authorization header.
/// </summary>
/// <param name="harness">The running proxy and its origins.</param>
[Collection(UpstreamRequestsSpecCollection.Name)]
public class when_a_session_request_reaches_a_service(UpstreamRequestsHarness harness) : IAsyncLifetime
{
    ForwardedRequest? _received;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        await client.SendAsync(UpstreamRequestsHarness.Request(UpstreamRequestsHarness.DefaultHost, "/api/orders", true));
        _received = harness.Default.LastRequestTo("/api/orders");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_forward_the_application_cookie() => Assert.Equal("theme=dark", _received!.Value("Cookie"));

    [Fact]
    public void should_not_forward_an_authorization_header() => Assert.False(_received!.Has("Authorization"));
}
