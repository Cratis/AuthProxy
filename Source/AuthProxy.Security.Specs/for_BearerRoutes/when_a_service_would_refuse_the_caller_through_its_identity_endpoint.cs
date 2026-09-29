// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// Under the default best-effort identity verification, a service answering <c language="text">403</c> on
/// <c language="text">/.cratis/me</c> refuses a browser session. A bearer route never calls that endpoint — it answers for
/// browser sessions, not for principals authenticated by a token — so the refusal does not apply there: the token is
/// forwarded, and the backend decides membership. This is the documented behavior, reported at startup, not an
/// oversight a token can exploit without the operator knowing.
/// </summary>
/// <param name="harness">The running proxy, with the default best-effort identity verification.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_a_service_would_refuse_the_caller_through_its_identity_endpoint(BearerRouteHarness harness) : IAsyncLifetime
{
    const string BearerPath = $"{BearerRouteHarness.RoutePrefix}/tools";
    const string BrowserPath = "/api/items";

    HttpResponseMessage? _bearer;
    HttpResponseMessage? _browser;
    bool _identityEndpointCalledForTheToken;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        harness.Origin.IdentityResponse = () => Results.StatusCode(StatusCodes.Status403Forbidden);

        try
        {
            _bearer = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, BearerPath, harness.Issuer.Token()));
            _identityEndpointCalledForTheToken = harness.Origin.ReceivedAnythingFor(WellKnownPaths.IdentityDetails);

            using var withSession = new HttpRequestMessage(HttpMethod.Get, BrowserPath);
            withSession.Headers.TryAddWithoutValidation(SecurityHarness.AuthenticatedUserHeader, "refused-browser-user");
            _browser = await client.SendAsync(withSession);
        }
        finally
        {
            harness.Origin.IdentityResponse = () => Results.Json(new { });
        }
    }

    public Task DisposeAsync()
    {
        _bearer?.Dispose();
        _browser?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_token() => Assert.Equal(HttpStatusCode.OK, _bearer!.StatusCode);
    [Fact] public void should_not_call_the_identity_endpoint_for_the_token() => Assert.False(_identityEndpointCalledForTheToken);
    [Fact] public void should_still_refuse_the_browser_session() => Assert.Equal(HttpStatusCode.Forbidden, _browser!.StatusCode);
    [Fact] public void should_not_forward_the_refused_browser_session() => Assert.False(harness.Origin.ReceivedAnythingFor(BrowserPath));
}
