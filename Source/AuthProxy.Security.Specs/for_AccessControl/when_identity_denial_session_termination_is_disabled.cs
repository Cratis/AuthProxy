// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>The default-off compatibility mode refuses without destroying the local cookie session.</summary>
public class when_identity_denial_session_termination_is_disabled : IAsyncLifetime
{
    RequiredVerificationHarness? _harness;
    HttpResponseMessage? _denial;
    HttpResponseMessage? _recovered;
    bool _forwardedOnDenial;
    bool _forwardedAfterRecovery;
    bool _authenticationCookieWasDeleted;

    public async Task InitializeAsync()
    {
        _harness = new RequiredVerificationHarness(terminateOnIdentityDenial: false);
        using var client = _harness.CreateSecurityClient();
        var session = _harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath);
        var cookie = session.Message.Headers.GetValues("Cookie").Single();

        _harness.FailEveryVerification();
        _harness.Origin.Clear();
        _denial = await client.SendAsync(session.Message);
        _forwardedOnDenial = _harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath);
        _authenticationCookieWasDeleted = session.AuthenticationCookieNames.Any(
            _ => RequiredVerificationHarness.Deletes(_denial, _));

        _harness.VerifyEveryCaller();
        _harness.Origin.Clear();
        using var retry = new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.ProtectedPath);
        retry.Headers.TryAddWithoutValidation("Cookie", cookie);
        _recovered = await client.SendAsync(retry);
        _forwardedAfterRecovery = _harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath);
    }

    public async Task DisposeAsync()
    {
        if (_harness is not null)
        {
            await _harness.DisposeAsync();
        }
    }

    [Fact]
    public void should_still_return_forbidden() =>
        Assert.Equal(HttpStatusCode.Forbidden, _denial!.StatusCode);

    [Fact]
    public void should_not_forward_the_denied_request() =>
        Assert.False(_forwardedOnDenial);

    [Fact]
    public void should_preserve_the_authentication_cookie() =>
        Assert.False(_authenticationCookieWasDeleted);

    [Fact]
    public void should_reuse_the_same_session_after_verification_recovers() =>
        Assert.Equal(HttpStatusCode.OK, _recovered!.StatusCode);

    [Fact]
    public void should_forward_after_verification_recovers() =>
        Assert.True(_forwardedAfterRecovery);
}
