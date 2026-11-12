// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using System.Security.Claims;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_SessionLifetime;

public class when_a_provider_has_a_shorter_session
{
    [Fact]
    public async Task should_ignore_hostile_lifetime_claims_properties_and_request_values()
    {
        await using var harness = new given.a_provider_session();
        using var client = harness.CreateSecurityClient();
        var authentication = harness.Services.GetRequiredService<IOptionsMonitor<C.Authentication>>().CurrentValue;
        var global = harness.Services.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue.Session;
        var http = new DefaultHttpContext { RequestServices = harness.Services };
        http.Request.Headers["Session:Lifetime"] = "24:00:00";
        http.Request.QueryString = new QueryString("?Session:Lifetime=24:00:00&Session:SlidingExpiration=true");
        var properties = new AuthenticationProperties { ExpiresUtc = harness.Clock.GetUtcNow().AddDays(1), AllowRefresh = true };
        properties.Items["Session:Lifetime"] = "24:00:00";
        properties.Items["urn:cratis:session:lifetime"] = "24:00:00";
        http.User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "subject"),
                new Claim("Session:Lifetime", "24:00:00"),
                new Claim("urn:cratis:session:lifetime", "24:00:00"),
                new Claim(".expires", harness.Clock.GetUtcNow().AddDays(1).ToString("O"))
            ],
            "provider-one"));
        var policy = SessionLifetimePolicy.Resolve(global, authentication, "provider-one");
        policy.Apply(properties, harness.Clock);
        Assert.Equal(TimeSpan.FromHours(1), properties.ExpiresUtc - properties.IssuedUtc);
        Assert.False(properties.AllowRefresh);
        var cookie = harness.Services.GetRequiredService<IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>().Get("Cookies");
        Assert.False(cookie.SlidingExpiration);
    }

    [Fact]
    public async Task should_refuse_an_above_global_lifetime_at_startup()
    {
        await using var harness = new given.a_provider_session("13:00:00");
        var exception = Assert.Throws<OptionsValidationException>(harness.CreateSecurityClient);
        Assert.Contains("Provider One", exception.Message);
        Assert.Contains("'13:00:00' exceeds the global session lifetime", exception.Message);
        Assert.Contains("The effective global Cratis:AuthProxy:Session:Lifetime ceiling is '12:00:00'", exception.Message);
        Assert.Contains("Cratis:AuthProxy:Authentication:OidcProviders[0]:Session:Lifetime", exception.Message);
        Assert.Contains("Set it to a value above 00:00:00 and no longer than '12:00:00', or remove the provider's Session:Lifetime to inherit the global value.", exception.Message);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task should_preserve_bearer_admission_and_ambiguous_credential_rejection(bool valid, bool withSession)
    {
        await using var harness = new given.a_provider_session();
        harness.VerifyEveryCaller();
        using var client = harness.CreateSecurityClient();
        using var request = withSession
            ? harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath).Message
            : new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.ProtectedPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", valid ? harness.Token() : "invalid-spec-token");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var admitted = valid && !withSession;
        Assert.Equal(admitted ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, response.StatusCode);
        if (admitted) Assert.Equal(CredentialSelectionHarness.TokenTenant, harness.Origin.LastRequestTo(RequiredVerificationHarness.ProtectedPath).Value(Headers.TenantId));
        else Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_keep_the_forwarded_identity_contract_unchanged()
    {
        await using var baseline = new CredentialSelectionHarness();
        await using var configured = new given.a_provider_session();
        var before = await Forward(baseline);
        var after = await Forward(configured);
        Assert.Equal(before.Headers.Keys.Order().ToArray(), after.Headers.Keys.Order().ToArray());
        Assert.Equal(PrincipalFields(before), PrincipalFields(after));
    }

    static string[] PrincipalFields(ForwardedRequest request)
    {
        using var principal = System.Text.Json.JsonDocument.Parse(Convert.FromBase64String(request.Value(Headers.Principal)));
        return principal.RootElement.EnumerateObject().Select(property => property.Name).Order().ToArray();
    }

    static async Task<ForwardedRequest> Forward(CredentialSelectionHarness harness)
    {
        harness.VerifyEveryCaller();
        using var client = harness.CreateSecurityClient();
        using var request = harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath).Message;
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return Assert.IsType<ForwardedRequest>(harness.Origin.LastRequestTo(RequiredVerificationHarness.ProtectedPath));
    }
}
