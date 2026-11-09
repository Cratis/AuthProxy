// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Security.for_SchemeSelection;

public class when_signing_in_with_a_stale_session
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_complete_the_provider_callback_before_refusing_application_authentication(bool withBearer)
    {
        await using var harness = new SessionCookieHarness();
        using var client = harness.CreateSecurityClient();
        if (withBearer) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-spec-token");
        var handshake = await ProviderBrowser.SignIn(client, SessionCookieHarness.ConsoleHost, "/welcome", $"{harness.CookieName}=invalid-spec-session");

        Assert.Equal(HttpStatusCode.Found, handshake.Challenge.StatusCode);
        Assert.NotNull(handshake.Callback);
        Assert.Equal(HttpStatusCode.Found, handshake.Callback.StatusCode);
        Assert.Equal("/welcome", handshake.Callback.Headers.Location!.ToString());
        Assert.NotEmpty(handshake.Session);
    }

    [Fact]
    public async Task should_keep_login_selection_reachable()
    {
        await using var harness = new SessionCookieHarness();
        using var client = harness.CreateSecurityClient();
        using var request = SessionCookieHarness.Request(
            SessionCookieHarness.ConsoleHost,
            $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.InvalidSession}",
            $"{harness.CookieName}=invalid-spec-session");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-spec-token");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
