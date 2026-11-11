// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;

namespace Cratis.AuthProxy.Security.for_SchemeSelection;

public class when_local_authentication_endpoints_are_matched
{
    [Theory]
    [InlineData(WellKnownPaths.Logout)]
    [InlineData("/.CRATIS/LOGOUT")]
    [InlineData("/.cratis/logout/")]
    [InlineData(WellKnownPaths.LogoutCallback)]
    public async Task should_keep_local_logout_reachable(string path)
    {
        await using var harness = new SessionCookieHarness();
        using var client = harness.CreateSecurityClient();
        using var request = SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, path, $"{harness.CookieName}=invalid-spec-session");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-spec-token");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains(SessionCookieHarness.SetCookies(response), value => SessionCookieHarness.IsDeletionOf(new() { Header = value, Name = harness.CookieName }));
    }

    [Theory]
    [InlineData("/.CRATIS/LOGIN/", "")]
    [InlineData("/.cratis/login/", "/")]
    public async Task should_keep_matched_provider_challenges_reachable(string prefix, string suffix)
    {
        await using var harness = new SessionCookieHarness();
        using var client = harness.CreateSecurityClient();
        var path = $"{prefix}{SessionCookieHarness.ProviderScheme}{suffix}";
        using var request = SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, path, $"{harness.CookieName}=invalid-spec-session");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-spec-token");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
    }
}
