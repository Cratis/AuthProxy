// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.for_Registration;

/// <summary>New users return to registration before any tenant membership is required.</summary>
/// <param name="harness">The deployment with real session and OAuth handlers.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_registration_uses_provider_selection(SessionCookieHarness harness)
{
    const string RegistrationDestination = "http://registration.example.test/welcome";

    static async Task<HttpResponseMessage> ChooseProvider(HttpClient client, HttpResponseMessage start, string[] pending)
    {
        var chooser = start.Headers.Location!.ToString();
        var returnUrl = QueryHelpers.ParseQuery(new Uri(new Uri("http://local.test"), chooser).Query)["returnUrl"].ToString();
        Assert.Equal(WellKnownPaths.Registration, returnUrl);
        using var request = SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, chooser, pending);
        request.Headers.Add("Sec-Fetch-Dest", "document");
        using var page = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("returnUrl", await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
        var login = QueryHelpers.AddQueryString($"{WellKnownPaths.LoginPrefix}/{SessionCookieHarness.ProviderScheme}", "returnUrl", returnUrl);
        return await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, login, pending), TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_complete_for_a_new_non_member(bool multipleProviders)
    {
        await using var deployment = Configure(multipleProviders);
        using var client = deployment.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        harness.ConsoleOrigin.TenantsResponse = () => Results.Json(Array.Empty<object>());
        harness.ClearOrigins();
        using var start = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, WellKnownPaths.Registration), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, start.StatusCode);
        var pending = SessionCookieHarness.SessionFrom(start);
        Assert.Contains(pending, cookie => cookie.StartsWith($"{Cookies.Registration}=", StringComparison.Ordinal));

        using var choice = multipleProviders ? await ChooseProvider(client, start, pending) : null;
        var challenge = choice ?? start;
        var authorization = challenge.Headers.Location!;
        Assert.StartsWith(SessionCookieHarness.ProviderAuthorizationEndpoint, authorization.ToString(), StringComparison.Ordinal);
        var state = QueryHelpers.ParseQuery(authorization.Query)["state"].ToString();
        var correlation = SessionCookieHarness.SessionFrom(challenge);
        using var callbackRequest = SessionCookieHarness.Request(
            SessionCookieHarness.ConsoleHost,
            $"/signin-{SessionCookieHarness.ProviderScheme}?code=test-code&state={Uri.EscapeDataString(state)}",
            [.. pending, .. correlation]);
        using var callback = await client.SendAsync(callbackRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        Assert.Equal(WellKnownPaths.Registration, callback.Headers.Location!.ToString());

        using var completionRequest = SessionCookieHarness.Request(
            SessionCookieHarness.ConsoleHost,
            callback.Headers.Location.ToString(),
            [.. pending, .. SessionCookieHarness.SessionFrom(callback)]);
        using var completion = await client.SendAsync(completionRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, completion.StatusCode);
        Assert.StartsWith(RegistrationDestination, completion.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.Contains(SessionCookieHarness.SetCookies(completion), cookie => SessionCookieHarness.IsDeletionOf(new() { Header = cookie, Name = Cookies.Registration }));
        Assert.DoesNotContain(harness.ConsoleOrigin.Received, request => request.Path == RecordingBackend.TenantsPath);
    }

    [Theory]
    [InlineData("https://outside.example.test/register")]
    [InlineData("http://console.example.test/register")]
    [InlineData("//outside.example.test/register")]
    [InlineData("/\\outside.example.test/register")]
    public async Task should_reject_a_foreign_registration_destination(string returnUrl)
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        foreach (var endpoint in new[] { WellKnownPaths.LoginPage, $"{WellKnownPaths.LoginPrefix}/{SessionCookieHarness.ProviderScheme}" })
        {
            using var request = SessionCookieHarness.Request(
                SessionCookieHarness.ConsoleHost,
                QueryHelpers.AddQueryString(endpoint, "returnUrl", returnUrl),
                $"{Cookies.Registration}=true");
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.Empty(SessionCookieHarness.SessionFrom(response));
        }

        Assert.Empty(harness.ConsoleOrigin.Received);
    }

    [Theory]
    [InlineData(Cookies.Registration, null, true)]
    [InlineData(Cookies.Registration, "/", false)]
    [InlineData(Cookies.Registration, "/api/private", false)]
    [InlineData(Cookies.InviteToken, null, true)]
    [InlineData(Cookies.InviteToken, "/", false)]
    public async Task should_resume_normal_sign_in_after_abandoning_the_pending_flow(string pendingCookie, string? returnUrl, bool useChooser)
    {
        await using var deployment = Configure(multipleProviders: true);
        using var client = deployment.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        string[] pending = [$"{pendingCookie}=abandoned", $"{Cookies.InvitationEntryState}=abandoned-state"];
        var chooserUrl = returnUrl is null ? WellKnownPaths.LoginPage : QueryHelpers.AddQueryString(WellKnownPaths.LoginPage, "returnUrl", returnUrl);
        using var chooserRequest = SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, chooserUrl, pending);
        chooserRequest.Headers.Add("Sec-Fetch-Dest", "document");
        using var page = useChooser ? await client.SendAsync(chooserRequest, TestContext.Current.CancellationToken) : null;
        if (page is not null) Assert.Equal(HttpStatusCode.OK, page.StatusCode);

        var login = $"{WellKnownPaths.LoginPrefix}/{SessionCookieHarness.ProviderScheme}";
        if (returnUrl is not null) login = QueryHelpers.AddQueryString(login, "returnUrl", returnUrl);
        using var challengeRequest = SessionCookieHarness.Request(SessionCookieHarness.ConsoleHost, login, useChooser ? [] : pending);
        using var challenge = await client.SendAsync(challengeRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, challenge.StatusCode);
        var abandoned = page ?? challenge;
        Assert.Contains(SessionCookieHarness.SetCookies(abandoned), cookie => SessionCookieHarness.IsDeletionOf(new() { Header = cookie, Name = pendingCookie }));
        Assert.Contains(SessionCookieHarness.SetCookies(abandoned), cookie => SessionCookieHarness.IsDeletionOf(new() { Header = cookie, Name = Cookies.InvitationEntryState }));
        Assert.StartsWith(SessionCookieHarness.ProviderAuthorizationEndpoint, challenge.Headers.Location.ToString(), StringComparison.Ordinal);
        var state = QueryHelpers.ParseQuery(challenge.Headers.Location.Query)["state"].ToString();
        using var callbackRequest = SessionCookieHarness.Request(
            SessionCookieHarness.ConsoleHost,
            $"/signin-{SessionCookieHarness.ProviderScheme}?code=test-code&state={Uri.EscapeDataString(state)}",
            SessionCookieHarness.SessionFrom(challenge));
        using var callback = await client.SendAsync(callbackRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        Assert.Equal(returnUrl ?? "/", callback.Headers.Location.ToString());
        Assert.NotEmpty(SessionCookieHarness.SessionFrom(callback));
    }

    WebApplicationFactory<Program> Configure(bool multipleProviders) => harness.WithWebHostBuilder(builder =>
    {
        if (multipleProviders)
        {
            builder.UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:1:Name", "SecondProvider")
                .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:1:AuthorizationEndpoint", "http://second-idp.test/authorize")
                .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:1:TokenEndpoint", "http://second-idp.test/token")
                .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:1:UserInformationEndpoint", "http://second-idp.test/user")
                .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:1:ClientId", "test-client")
                .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:1:ClientSecret", "test-secret");
        }

        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:PagesPath"] = Path.Combine(AppContext.BaseDirectory, "Pages"),
            [$"{C.AuthProxy.SectionKey}:Invite:Lobby:Registration:BaseUrl"] = RegistrationDestination,
            [$"{C.AuthProxy.SectionKey}:Tenants:{SessionCookieHarness.TenantId}:Domains:0"] = SessionCookieHarness.ConsoleHost,
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = "Host",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Strategy"] = "Selection",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options:EndpointUrl"] = harness.ConsoleOrigin.TenantsUrl,
        }));
    });
}
