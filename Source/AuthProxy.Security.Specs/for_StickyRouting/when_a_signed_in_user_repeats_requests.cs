// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;

namespace Cratis.AuthProxy.Security.for_StickyRouting;

/// <summary>Affinity pins a browser, but never leaks the pin or changes the token and Host contract at the origin.</summary>
/// <param name="harness">The proxy and its two discovered replicas.</param>
[Collection(StickyRoutingSpecCollection.Name)]
public class when_a_signed_in_user_repeats_requests(StickyRoutingHarness harness) : IAsyncLifetime
{
    string _setCookie = string.Empty;
    string _cookie = string.Empty;
    RecordingBackend? _pinned;
    RecordingBackend? _other;
    readonly List<HttpStatusCode> _statuses = [];

    public async ValueTask InitializeAsync()
    {
        harness.ClearOrigins();
        harness.Replica.Clear();
        using var client = harness.CreateSecurityClient();
        using var first = await client.SendAsync(AccessTokenForwardingHarness.FromSession("/api/first", "session-one"));
        _statuses.Add(first.StatusCode);
        _setCookie = first.Headers.GetValues("Set-Cookie").Single(value => value.StartsWith(".cratis-affinity-reporting=", StringComparison.Ordinal));
        _cookie = _setCookie.Split(';')[0];
        _pinned = harness.Backend.ReceivedAnythingFor("/api/first") ? harness.Backend : harness.Replica;
        _other = ReferenceEquals(_pinned, harness.Backend) ? harness.Replica : harness.Backend;
        for (var i = 0; i < 10; i++)
        {
            using var request = AccessTokenForwardingHarness.FromSession("/api/repeat", "session-one");
            request.Headers.TryAddWithoutValidation("Cookie", _cookie);
            using var response = await client.SendAsync(request);
            _statuses.Add(response.StatusCode);
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_succeed() => Assert.All(_statuses, status => Assert.Equal(HttpStatusCode.OK, status));
    [Fact] public void should_keep_every_request_on_the_first_replica() => Assert.Equal(11, _pinned.Received.Count);
    [Fact] public void should_not_send_any_request_to_the_other_replica() => Assert.Empty(_other.Received);
    [Fact]
    public void should_set_a_host_only_session_cookie_with_safe_flags()
    {
        Assert.Contains("httponly", _setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", _setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", _setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", _setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("expires=", _setCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void should_never_forward_the_affinity_cookie() =>
        Assert.All(harness.Backend.Received.Concat(harness.Replica.Received), request => Assert.DoesNotContain(".cratis-affinity-", request.Value("Cookie"), StringComparison.Ordinal));

    [Fact]
    public void should_not_disclose_replica_addresses_in_the_cookie()
    {
        Assert.DoesNotContain("127.0.0.1", _cookie, StringComparison.Ordinal);
        Assert.DoesNotContain(new Uri(harness.Backend.BaseUrl).Port.ToString(CultureInfo.InvariantCulture), _cookie, StringComparison.Ordinal);
        Assert.DoesNotContain(new Uri(harness.Replica.BaseUrl).Port.ToString(CultureInfo.InvariantCulture), _cookie, StringComparison.Ordinal);
    }

    [Fact]
    public void should_forward_the_users_token_to_the_replica() =>
        Assert.All(_pinned.Received, request => Assert.Equal("Bearer user-token-for-session-one", request.Value("Authorization")));

    [Fact]
    public void should_send_the_configured_service_authority_as_host() =>
        Assert.All(harness.Backend.Received.Concat(harness.Replica.Received), request => Assert.Equal(new Uri(harness.Backend.BaseUrl).Authority, request.Value("Host")));
}
