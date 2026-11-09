// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_SchemeSelection;

public class when_a_bearer_and_session_are_presented
{
    [Theory]
    [InlineData("invalid", true)]
    [InlineData("valid", true)]
    [InlineData("expired", true)]
    [InlineData("invalid", false)]
    [InlineData("expired", false)]
    public async Task should_refuse_without_forwarding(string tokenKind, bool withSession)
    {
        await using var harness = new CredentialSelectionHarness();
        harness.VerifyEveryCaller();
        using var client = harness.CreateSecurityClient();
        var token = harness.Token();
        if (tokenKind == "invalid") token = token[..^8];
        if (tokenKind == "expired") harness.Clock.Advance(TimeSpan.FromHours(2));

        using var request = withSession
            ? harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath).Message
            : new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.ProtectedPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_preserve_anonymous_routes(bool withSession)
    {
        await using var harness = new CredentialSelectionHarness();
        using var client = harness.CreateSecurityClient();
        using var request = withSession
            ? harness.AuthenticatedRequest(RequiredVerificationHarness.AnonymousPath).Message
            : new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.AnonymousPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-spec-token");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var forwarded = harness.Origin.LastRequestTo(RequiredVerificationHarness.AnonymousPath);
        Assert.False(forwarded.Has(Headers.Principal));
        Assert.False(forwarded.Has(Headers.TenantId));
    }

    [Fact]
    public async Task should_authenticate_a_bearer_without_a_session()
    {
        await using var harness = new CredentialSelectionHarness();
        harness.VerifyEveryCaller();
        using var client = harness.CreateSecurityClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.ProtectedPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", harness.Token());
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(CredentialSelectionHarness.TokenTenant,
            harness.Origin.LastRequestTo(RequiredVerificationHarness.ProtectedPath).Value(Headers.TenantId));
    }

    [Fact]
    public async Task should_authenticate_the_other_tenants_session_without_a_bearer()
    {
        await using var harness = new CredentialSelectionHarness();
        harness.VerifyEveryCaller();
        using var client = harness.CreateSecurityClient();
        using var request = harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath).Message;
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(RequiredVerificationHarness.TenantId,
            harness.Origin.LastRequestTo(RequiredVerificationHarness.ProtectedPath).Value(Headers.TenantId));
        Assert.NotEqual(CredentialSelectionHarness.TokenTenant, RequiredVerificationHarness.TenantId);
    }

    [Theory]
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    [InlineData("Bearer\tinvalid-spec-token")]
    public async Task should_refuse_an_incomplete_bearer_with_a_session(string authorization)
    {
        await using var harness = new CredentialSelectionHarness();
        using var client = harness.CreateSecurityClient();
        using var request = harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath).Message;
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_refuse_an_expired_session()
    {
        await using var harness = new CredentialSelectionHarness();
        using var client = harness.CreateSecurityClient();
        var options = harness.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "session-user")], "Cookies"));
        var properties = new AuthenticationProperties { ExpiresUtc = harness.Clock.GetUtcNow().AddMinutes(1) };
        var ticket = new AuthenticationTicket(principal, properties, "Cookies");
        var cookieContext = new DefaultHttpContext();
        options.CookieManager.AppendResponseCookie(cookieContext, options.Cookie.Name!, options.TicketDataFormat.Protect(ticket), new CookieOptions());
        harness.Clock.Advance(TimeSpan.FromMinutes(2));
        using var request = new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.ProtectedPath);
        request.Headers.TryAddWithoutValidation("Cookie", cookieContext.Response.Headers.SetCookie.Select(value => value!.Split(';')[0]));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }
}
