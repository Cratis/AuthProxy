// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessTokenForwarding;

/// <summary>
/// OWASP A01/A07. A backend that accepts the user's access token from AuthProxy must receive the token AuthProxy
/// obtained, never a value the browser sent, and must receive nothing at all when no token could be obtained. The
/// frontend never needs a token and never gets one.
/// </summary>
/// <param name="harness">The running proxy and its origins.</param>
[Collection(AccessTokenForwardingSpecCollection.Name)]
public class when_a_backend_receives_the_users_access_token(AccessTokenForwardingHarness harness) : IAsyncLifetime
{
    ForwardedRequest? _backendRequest;
    ForwardedRequest? _frontendRequest;
    HttpResponseMessage? _rejected;
    bool _backendSawTheRejectedSession;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.ClearOrigins();
        var request = AccessTokenForwardingHarness.FromSession("/api/orders", "session-one");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer forged-by-the-browser");
        await client.SendAsync(request);
        _backendRequest = harness.Backend.LastRequestTo("/api/orders");

        await client.SendAsync(AccessTokenForwardingHarness.FromSession("/dashboard", "session-one"));
        _frontendRequest = harness.Frontend.LastRequestTo("/dashboard");

        harness.ClearOrigins();
        _rejected = await client.SendAsync(AccessTokenForwardingHarness.FromSession("/api/orders", AccessTokenForwardingHarness.RejectedSession));
        _backendSawTheRejectedSession = harness.Backend.ReceivedAnythingFor("/api/orders");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_forward_the_users_access_token_to_the_backend() =>
        Assert.Equal($"Bearer {AccessTokenForwardingHarness.TokenFor("session-one")}", _backendRequest!.Value("Authorization"));

    [Fact]
    public void should_not_forward_an_authorization_header_to_the_frontend() =>
        Assert.False(_frontendRequest!.Has("Authorization"));

    [Fact]
    public void should_refuse_a_session_with_no_obtainable_token() =>
        Assert.Equal(HttpStatusCode.Unauthorized, _rejected!.StatusCode);

    [Fact]
    public void should_not_reach_the_backend_without_a_token() =>
        Assert.False(_backendSawTheRejectedSession);
}
