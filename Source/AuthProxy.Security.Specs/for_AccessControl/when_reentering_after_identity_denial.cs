// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>Session termination does not close the anonymous surfaces needed for a clean re-entry.</summary>
/// <param name="harness">The running proxy whose configuration enables session termination.</param>
[Collection(RequiredVerificationSpecCollection.Name)]
public class when_reentering_after_identity_denial(
    RequiredVerificationHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _providers;
    HttpResponseMessage? _anonymous;
    bool _anonymousWasForwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.DenyEveryCaller();
        using var denial = await client.SendAsync(
            harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath).Message);

        harness.Origin.Clear();
        _providers = await client.GetAsync(WellKnownPaths.Providers);
        _anonymous = await client.GetAsync(RequiredVerificationHarness.AnonymousPath);
        _anonymousWasForwarded = harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.AnonymousPath);
    }

    public Task DisposeAsync()
    {
        harness.VerifyEveryCaller();
        return Task.CompletedTask;
    }

    [Fact]
    public void should_keep_the_provider_surface_reachable() =>
        Assert.Equal(HttpStatusCode.OK, _providers!.StatusCode);

    [Fact]
    public void should_keep_the_declared_anonymous_route_reachable() =>
        Assert.Equal(HttpStatusCode.OK, _anonymous!.StatusCode);

    [Fact]
    public void should_forward_the_declared_anonymous_route() =>
        Assert.True(_anonymousWasForwarded);
}
