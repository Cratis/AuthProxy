// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_SchemeSelection;

public class when_a_browser_recovers_its_session
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_expire_a_failed_host_only_session_and_accept_a_new_session(bool expired)
    {
        await using var harness = new CredentialSelectionHarness();
        harness.VerifyEveryCaller();
        using var client = harness.CreateSecurityClient();
        using var request = FailedSession(harness, RequiredVerificationHarness.ProtectedPath, expired);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var deletions = SessionCookieHarness.SetCookies(response);
        Assert.Contains(deletions, value => SessionCookieHarness.IsDeletionOf(value, C.Session.DefaultCookieName));
        Assert.All(deletions, value => Assert.False(SessionCookieHarness.HasDomain(value)));
        if (expired)
        {
            Assert.Contains(deletions, value => SessionCookieHarness.IsDeletionOf(value, $"{C.Session.DefaultCookieName}C1"));
        }

        Assert.Empty(harness.Origin.Received);
        using var recovered = harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath).Message;
        using var result = await client.SendAsync(recovered, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task should_allow_local_logout_and_clear_the_session(bool expired, bool withBearer)
    {
        await using var harness = new CredentialSelectionHarness();
        using var client = harness.CreateSecurityClient();
        using var request = FailedSession(harness, WellKnownPaths.Logout, expired);
        if (withBearer) request.Headers.TryAddWithoutValidation("Authorization", "Bearer invalid-spec-token");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains(SessionCookieHarness.SetCookies(response), value => SessionCookieHarness.IsDeletionOf(value, C.Session.DefaultCookieName));
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData(WellKnownPaths.IdentityDetails)]
    [InlineData(WellKnownPaths.SelectTenant)]
    public async Task should_refuse_a_failed_session_on_identity_and_tenant_endpoints(string path)
    {
        await using var harness = new CredentialSelectionHarness();
        using var client = harness.CreateSecurityClient();
        using var request = FailedSession(harness, path, expired: true);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(SessionCookieHarness.SetCookies(response), value => SessionCookieHarness.IsDeletionOf(value, C.Session.DefaultCookieName));
        Assert.Empty(harness.Origin.Received);
    }

    static HttpRequestMessage FailedSession(CredentialSelectionHarness harness, string path, bool expired)
    {
        var options = harness.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var context = new DefaultHttpContext();
        var value = "invalid-spec-session";
        if (expired)
        {
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "session-user"), new Claim("padding", new string('x', 6000))], "Cookies"));
            var properties = new AuthenticationProperties { ExpiresUtc = harness.Clock.GetUtcNow().AddMinutes(1) };
            value = options.TicketDataFormat.Protect(new AuthenticationTicket(principal, properties, "Cookies"));
            harness.Clock.Advance(TimeSpan.FromMinutes(2));
        }

        options.CookieManager.AppendResponseCookie(context, options.Cookie.Name!, value, new CookieOptions());
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", context.Response.Headers.SetCookie.Select(cookie => cookie!.Split(';')[0])));
        return request;
    }
}
