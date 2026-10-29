// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>A session that records no provider ends when several providers are configured.</summary>
public class when_a_session_without_a_recorded_provider_arrives_with_several_providers : IAsyncLifetime
{
    RequiredVerificationHarness? _harness;
    HttpResponseMessage? _response;
    bool _forwarded;
    bool _authenticationCookieWasDeleted;

    public async ValueTask InitializeAsync()
    {
        _harness = new RequiredVerificationHarness(terminateOnIdentityDenial: true, secondProvider: true);
        using var client = _harness.CreateSecurityClient();
        _harness.VerifyEveryCaller();
        var session = _harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath);

        _harness.Origin.Clear();
        _response = await client.SendAsync(session.Message);
        _forwarded = _harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath);
        _authenticationCookieWasDeleted = session.AuthenticationCookieNames.Any(
            _ => RequiredVerificationHarness.Deletes(_response, _));
    }

    public async ValueTask DisposeAsync()
    {
        if (_harness is not null)
        {
            await _harness.DisposeAsync();
        }
    }

    [Fact]
    public void should_answer_unauthorized() =>
        Assert.Equal(HttpStatusCode.Unauthorized, _response!.StatusCode);

    [Fact]
    public void should_not_forward_the_request() =>
        Assert.False(_forwarded);

    [Fact]
    public void should_delete_the_authentication_cookie() =>
        Assert.True(_authenticationCookieWasDeleted);
}
