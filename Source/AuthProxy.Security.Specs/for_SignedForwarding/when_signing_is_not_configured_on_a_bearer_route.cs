// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// A bearer route of a deployment that does not sign never passes on an assertion the caller wrote.
/// </summary>
/// <param name="harness">The running unsigned proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_signing_is_not_configured_on_a_bearer_route(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/unsigned";

    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        var request = BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.Token());
        request.Headers.TryAddWithoutValidation(Headers.ForwardedIdentity, "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.forged");
        _response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(Path);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.NotNull(_forwarded);
    [Fact] public void should_not_forward_an_assertion() => Assert.False(_forwarded!.Has(Headers.ForwardedIdentity));
}
