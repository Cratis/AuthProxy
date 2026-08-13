// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// Required verification has one terminal negative outcome. Whether the origin states no, is unavailable,
/// or answers something that cannot be a verdict, the running ingress must refuse before forwarding and
/// terminate the local cookie session without starting an external-provider logout.
/// </summary>
/// <param name="harness">The running proxy whose configuration enables session termination.</param>
[Collection(RequiredVerificationSpecCollection.Name)]
public class when_identity_denial_terminates_the_local_session(
    RequiredVerificationHarness harness) : IAsyncLifetime
{
    static readonly Action<RequiredVerificationHarness>[] _denials =
    [
        _ => _.DenyEveryCaller(),
        _ => _.FailEveryVerification(),
        _ => _.AnswerWithoutVerdict(),
        _ => _.AnswerWithMalformedJson(),
        _ => _.AnswerWithConflictingVerdicts()
    ];

    readonly List<HttpStatusCode> _statuses = [];
    readonly List<bool> _forwarded = [];
    readonly List<bool> _forbiddenPages = [];
    readonly List<bool> _redirected = [];
    readonly List<string> _missingCookieExpiries = [];

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var deny in _denials)
        {
            deny(harness);
            harness.Origin.Clear();
            var session = harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath);
            using var response = await client.SendAsync(session.Message);
            _statuses.Add(response.StatusCode);
            _forwarded.Add(harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath));
            _forbiddenPages.Add(
                (await response.Content.ReadAsStringAsync())
                    .Contains(RequiredVerificationHarness.ForbiddenMarker, StringComparison.Ordinal));
            _redirected.Add(response.Headers.Location is not null);

            var expected = session.AuthenticationCookieNames.Concat(
            [
                Cookies.Identity,
                Cookies.IdentityAuthorization,
                Cookies.Tenant,
                Cookies.Tenants,
                Cookies.InviteToken,
                Cookies.InvitationEntryState,
                Cookies.Registration,
                Cookies.Providers,
                RequiredVerificationHarness.CorrelationCookie,
                RequiredVerificationHarness.NonceCookie,
                RequiredVerificationHarness.AdditionalSessionCookie
            ]);
            _missingCookieExpiries.AddRange(
                expected.Where(_ => !RequiredVerificationHarness.Deletes(response, _)));
        }
    }

    public Task DisposeAsync()
    {
        harness.VerifyEveryCaller();
        return Task.CompletedTask;
    }

    [Fact]
    public void should_return_forbidden_for_every_negative_outcome() =>
        Assert.All(_statuses, _ => Assert.Equal(HttpStatusCode.Forbidden, _));

    [Fact]
    public void should_serve_the_forbidden_page_for_every_negative_outcome() =>
        Assert.All(_forbiddenPages, Assert.True);

    [Fact]
    public void should_never_forward_the_protected_request() =>
        Assert.DoesNotContain(true, _forwarded);

    [Fact]
    public void should_expire_the_complete_owned_session() =>
        Assert.Empty(_missingCookieExpiries);

    [Fact]
    public void should_not_initiate_external_provider_logout() =>
        Assert.DoesNotContain(true, _redirected);
}
