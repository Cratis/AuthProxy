// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>Tenant-less Required refusal reaches the same local-session termination boundary.</summary>
/// <param name="harness">The running proxy whose configuration enables session termination.</param>
[Collection(RequiredVerificationSpecCollection.Name)]
public class when_required_verification_has_no_tenant(
    RequiredVerificationHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;
    bool _forwarded;
    IReadOnlyList<string> _authenticationCookies = [];

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.VerifyEveryCaller();
        harness.Origin.Clear();
        var session = harness.AuthenticatedRequest(
            RequiredVerificationHarness.ProtectedPath,
            includeTenant: false,
            passTenancyWithoutTenant: true);
        _authenticationCookies = session.AuthenticationCookieNames;
        _response = await client.SendAsync(session.Message);
        _forwarded = harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath);
    }

    public Task DisposeAsync()
    {
        harness.VerifyEveryCaller();
        return Task.CompletedTask;
    }

    [Fact]
    public void should_return_forbidden() =>
        Assert.Equal(HttpStatusCode.Forbidden, _response!.StatusCode);

    [Fact]
    public void should_not_forward_the_request() =>
        Assert.False(_forwarded);

    [Fact]
    public void should_expire_the_primary_cookie_and_chunks() =>
        Assert.All(
            _authenticationCookies,
            _ => Assert.True(RequiredVerificationHarness.Deletes(_response!, _)));

    [Fact]
    public void should_not_start_provider_logout() =>
        Assert.Null(_response!.Headers.Location);
}
