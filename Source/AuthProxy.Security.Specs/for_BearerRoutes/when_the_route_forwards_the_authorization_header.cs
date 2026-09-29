// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A route that sets <c language="text">ForwardAuthorizationHeader</c> sends the token on to the backend alongside the
/// principal AuthProxy vouches for. It is the only thing that changes: cookies still stay at the edge.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_route_forwards_the_authorization_header(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.ForwardingRoutePrefix}/items";

    string _token = string.Empty;
    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _token = harness.Issuer.Token();
        var request = BearerRouteHarness.WithToken(HttpMethod.Get, Path, _token);
        request.Headers.TryAddWithoutValidation("Cookie", ".cratis-session=some-session");

        using var response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(Path);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_request() => Assert.NotNull(_forwarded);
    [Fact] public void should_forward_the_token() => Assert.Equal($"Bearer {_token}", _forwarded!.Value("Authorization"));
    [Fact] public void should_still_forward_the_principal() => Assert.Equal(BearerRouteHarness.AccountId, _forwarded!.Value(Headers.PrincipalId));
    [Fact] public void should_not_forward_the_cookie() => Assert.False(_forwarded!.Has("Cookie"));
}
