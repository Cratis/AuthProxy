// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_UpstreamRequests;

/// <summary>
/// A request to an anonymous path keeps the Authorization header the caller sent, and AuthProxy cookies are still removed.
/// </summary>
/// <param name="harness">The running proxy and its origins.</param>
[Collection(UpstreamRequestsSpecCollection.Name)]
public class when_a_request_reaches_an_anonymous_path_with_an_authorization_header(UpstreamRequestsHarness harness) : IAsyncLifetime
{
    ForwardedRequest? _received;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        await client.SendAsync(UpstreamRequestsHarness.Request(UpstreamRequestsHarness.DefaultHost, UpstreamRequestsHarness.AnonymousPath, false));
        _received = harness.Default.LastRequestTo(UpstreamRequestsHarness.AnonymousPath);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_forward_the_authorization_header() => Assert.Equal("Bearer callers-own-token", _received!.Value("Authorization"));

    [Fact]
    public void should_forward_only_the_application_cookie() => Assert.Equal("theme=dark", _received!.Value("Cookie"));
}
