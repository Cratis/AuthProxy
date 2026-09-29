// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A bearer route has no browser session to verify through <c language="text">/.cratis/me</c>. In a deployment that
/// requires identity verification it serves requests only because the route says it accepts callers without it, and
/// it then forwards without asking the backend for a verdict.
/// </summary>
/// <param name="harness">The running proxy, with identity verification required.</param>
[Collection(GatedBearerRouteSpecCollection.Name)]
public class when_the_deployment_requires_identity_verification(GatedBearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";

    HttpResponseMessage? _response;
    bool _verified;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(BearerRouteHarness.WithToken(
            HttpMethod.Get,
            Path,
            harness.Issuer.Token(new Dictionary<string, object> { [GatedBearerRouteHarness.RequiredClaim] = GatedBearerRouteHarness.RequiredValue })));
        _verified = harness.Origin.ReceivedAnythingFor(WellKnownPaths.IdentityDetails);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_not_ask_the_backend_for_a_verdict() => Assert.False(_verified);
}
