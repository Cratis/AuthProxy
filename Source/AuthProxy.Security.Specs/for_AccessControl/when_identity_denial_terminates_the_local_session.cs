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
    /// <summary>Outcomes where the caller was refused: the session ends.</summary>
    static readonly Action<RequiredVerificationHarness>[] _denials =
    [
        _ => _.DenyEveryCaller(),
        _ => _.AnswerWithoutVerdict(),
        _ => _.AnswerWithConflictingVerdicts()
    ];

    /// <summary>Outcomes where verification could not be completed: nobody refused anyone, so the caller is told the service is unavailable and the session is left alone.</summary>
    static readonly Action<RequiredVerificationHarness>[] _unavailable =
    [
        _ => _.FailEveryVerification(),
        _ => _.AnswerWithMalformedJson()
    ];

    readonly List<HttpStatusCode> _unavailableStatuses = [];
    readonly List<bool> _unavailableForwarded = [];
    readonly List<bool> _unavailablePages = [];
    readonly List<bool> _sessionsEndedWhenUnavailable = [];

    readonly List<HttpStatusCode> _statuses = [];
    readonly List<bool> _forwarded = [];
    readonly List<bool> _forbiddenPages = [];
    readonly List<bool> _redirected = [];
    readonly List<string> _missingCookieExpiries = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var fail in _unavailable)
        {
            fail(harness);
            harness.Origin.Clear();
            var session = harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath);
            using var response = await client.SendAsync(session.Message);
            _unavailableStatuses.Add(response.StatusCode);
            _unavailableForwarded.Add(harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath));
            _unavailablePages.Add(
                (await response.Content.ReadAsStringAsync())
                    .Contains(RequiredVerificationHarness.UnavailableMarker, StringComparison.Ordinal));
            _sessionsEndedWhenUnavailable.Add(session.AuthenticationCookieNames.Any(_ => RequiredVerificationHarness.Deletes(response, _)));
        }

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

    public ValueTask DisposeAsync()
    {
        harness.VerifyEveryCaller();
        return ValueTask.CompletedTask;
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

    [Fact]
    public void should_answer_service_unavailable_when_verification_could_not_be_completed() =>
        Assert.All(_unavailableStatuses, _ => Assert.Equal(HttpStatusCode.ServiceUnavailable, _));

    [Fact]
    public void should_say_the_service_is_unavailable_instead_of_access_denied() =>
        Assert.All(_unavailablePages, Assert.True);

    [Fact]
    public void should_never_forward_the_request_when_verification_could_not_be_completed() =>
        Assert.DoesNotContain(true, _unavailableForwarded);

    [Fact]
    public void should_keep_the_session_when_verification_could_not_be_completed() =>
        Assert.DoesNotContain(true, _sessionsEndedWhenUnavailable);
}
