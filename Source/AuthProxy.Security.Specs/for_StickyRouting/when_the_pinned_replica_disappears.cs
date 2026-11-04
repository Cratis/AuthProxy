// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_StickyRouting;

/// <summary>
/// A stale affinity cookie must move to the remaining replica after discovery refreshes.
/// </summary>
[Collection(ReplicaRemovalSpecCollection.Name)]
public class when_the_pinned_replica_disappears : IAsyncLifetime
{
    const string AffinityName = ".cratis-affinity-reporting";
    const string AfterRemovalPath = "/api/after-removal";
    readonly ReplicaRemovalHarness _harness = new();
    readonly List<HttpStatusCode> _statuses = [];
    HttpClient _client = null!;
    bool _pinnedBackend;
    string _originalCookie = string.Empty;
    string _replacementCookie = string.Empty;
    ForwardedRequest[] _survivorRequests = [];
    int _removedCountAtMove;

    RecordingBackend Pinned => _pinnedBackend ? _harness.Backend : _harness.Replica;
    RecordingBackend Survivor => _pinnedBackend ? _harness.Replica : _harness.Backend;

    public async ValueTask InitializeAsync()
    {
        _client = _harness.CreateSecurityClient();
        _client.Timeout = TimeSpan.FromSeconds(5);
        await EstablishPin();

        _harness.Remove(Pinned);
        await WaitForMove();
        _removedCountAtMove = Pinned.Received.Count;
        Assert.NotEmpty(_replacementCookie);

        for (var index = 0; index < 5; index++)
        {
            using var request = ReplicaRemovalHarness.SignedIn(AfterRemovalPath, _replacementCookie);
            using var response = await _client.SendAsync(request);
            _statuses.Add(response.StatusCode);
        }

        _survivorRequests = Survivor.Received.Where(request => request.Path == AfterRemovalPath).ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        _client?.Dispose();
        await _harness.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public void should_move_the_stale_cookie_to_the_surviving_replica() =>
        Assert.True(Survivor.ReceivedAnythingFor("/api/await-removal"));

    [Fact]
    public void should_keep_requests_successful_during_and_after_the_refresh() =>
        Assert.All(_statuses, status => Assert.Equal(HttpStatusCode.OK, status));

    [Fact]
    public void should_replace_the_old_affinity_cookie() => Assert.NotEqual(_originalCookie, _replacementCookie);

    [Fact]
    public void should_keep_later_requests_on_the_surviving_replica() => Assert.Equal(5, _survivorRequests.Length);

    [Fact]
    public void should_stop_sending_requests_to_the_removed_replica() => Assert.Equal(_removedCountAtMove, Pinned.Received.Count);

    [Fact]
    public void should_preserve_the_configured_backend_host() =>
        Assert.All(_survivorRequests, request => Assert.Equal(new Uri(_harness.Backend.BaseUrl).Authority, request.Value("Host")));

    [Fact]
    public void should_preserve_the_users_authorization() =>
        Assert.All(_survivorRequests, request => Assert.Equal("Bearer user-token-for-session-one", request.Value("Authorization")));

    [Fact]
    public void should_not_forward_the_affinity_cookie_to_either_origin() =>
        Assert.All(_harness.Backend.Received.Concat(_harness.Replica.Received), request =>
            Assert.DoesNotContain(AffinityName, request.Value("Cookie"), StringComparison.Ordinal));

    async Task EstablishPin()
    {
        using var first = ReplicaRemovalHarness.SignedIn("/api/before-removal");
        using var response = await _client.SendAsync(first);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        _originalCookie = AffinityCookie(response);
        Assert.NotEmpty(_originalCookie);
        _pinnedBackend = _harness.Backend.ReceivedAnythingFor("/api/before-removal");
        Assert.Single(Pinned.Received, request => request.Path == "/api/before-removal");
        Assert.False(Survivor.ReceivedAnythingFor("/api/before-removal"));

        using var repeat = ReplicaRemovalHarness.SignedIn("/api/confirm-pin", _originalCookie);
        using var repeated = await _client.SendAsync(repeat);
        Assert.Equal(HttpStatusCode.OK, repeated.StatusCode);
        Assert.True(Pinned.ReceivedAnythingFor("/api/confirm-pin"));
        Assert.False(Survivor.ReceivedAnythingFor("/api/confirm-pin"));
    }

    async Task WaitForMove()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(100));
        do
        {
            using var request = ReplicaRemovalHarness.SignedIn("/api/await-removal", _originalCookie);
            using var response = await _client.SendAsync(request, timeout.Token);
            _statuses.Add(response.StatusCode);
            if (Survivor.ReceivedAnythingFor("/api/await-removal"))
            {
                _replacementCookie = AffinityCookie(response);
                return;
            }
        }
        while (await timer.WaitForNextTickAsync(timeout.Token));
    }

    static string AffinityCookie(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Where(value => value.StartsWith(AffinityName + "=", StringComparison.Ordinal)).Select(value => value.Split(';')[0]).SingleOrDefault() ?? string.Empty
            : string.Empty;
}
