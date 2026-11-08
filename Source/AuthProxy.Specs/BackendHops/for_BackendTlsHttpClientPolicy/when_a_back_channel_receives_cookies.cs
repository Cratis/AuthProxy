// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.AccessTokens;
using Cratis.AuthProxy.Admission;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.BearerRoutes;
using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsHttpClientPolicy;

public class when_a_back_channel_receives_cookies
{
    [Theory]
    [InlineData("", false)]
    [InlineData(ForwardedIdentityServiceCollectionExtensions.HttpClientName, false)]
    [InlineData(CapabilityVerifier.HttpClientName, false)]
    [InlineData(CapabilityVerifier.HttpClientName, true)]
    [InlineData(InvitationTokenKeys.HttpClientName, false)]
    [InlineData(BearerRouteDefaults.MetadataHttpClientName, false)]
    [InlineData(nameof(ClientCredentialsVerifier), false)]
    [InlineData(UserAccessTokens.HttpClientName, false)]
    public async Task should_not_carry_response_cookies_or_previous_request_identity_to_the_next_call(string clientName, bool requireTls)
    {
        var originBuilder = WebApplication.CreateSlimBuilder();
        originBuilder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var origin = originBuilder.Build();
        origin.MapGet("/seed", context =>
        {
            context.Response.Cookies.Append("session", "synthetic-session", new CookieOptions { Path = "/" });
            context.Response.Cookies.Append("principal", "synthetic-user", new CookieOptions { Path = "/" });
            context.Response.Cookies.Append("tenant", "synthetic-tenant", new CookieOptions { Path = "/" });
            return Task.CompletedTask;
        });
        origin.MapGet("/next", context => context.Response.WriteAsJsonAsync(
            context.Request.Headers.Keys.Order(StringComparer.OrdinalIgnoreCase).ToArray()));
        await origin.StartAsync(TestContext.Current.CancellationToken);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Development });
        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        builder.SetupReverseProxy();
        builder.AddInvites();
        builder.Services.Configure<C.AuthProxy>(config =>
        {
            config.Services.Clear();
            config.BackendTls.RequireTlsOnIdentityHops = requireTls;
        });
        await using var services = builder.Services.BuildServiceProvider();
        var factory = services.GetRequiredService<IHttpClientFactory>();
        using (var firstClient = factory.CreateClient(clientName))
        {
            using var first = new HttpRequestMessage(HttpMethod.Get, origin.Urls.Single() + "/seed");
            first.Headers.Add("Cookie", "caller-session=synthetic-caller");
            first.Headers.Add("Authorization", "Bearer synthetic-token");
            first.Headers.Add(Headers.Principal, "synthetic-principal");
            first.Headers.Add(Headers.TenantId, "synthetic-tenant");
            using var response = await firstClient.SendAsync(first, TestContext.Current.CancellationToken);
            response.EnsureSuccessStatusCode();
        }

        // A new client shares the factory's primary handler with the previous call.
        using var nextClient = factory.CreateClient(clientName);
        using var next = new HttpRequestMessage(HttpMethod.Get, origin.Urls.Single() + "/next");
        next.Headers.Accept.ParseAdd("application/json");
        using var nextResponse = await nextClient.SendAsync(next, TestContext.Current.CancellationToken);
        nextResponse.EnsureSuccessStatusCode();
        var headers = JsonSerializer.Deserialize<string[]>(await nextResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        headers.ShouldContain("Accept");
        headers.ShouldNotContain(header => string.Equals(header, "Cookie", StringComparison.OrdinalIgnoreCase));
        headers.ShouldNotContain(header => string.Equals(header, "Authorization", StringComparison.OrdinalIgnoreCase));
        headers.ShouldNotContain(header => header.StartsWith("X-MS-CLIENT-", StringComparison.OrdinalIgnoreCase));
        headers.ShouldNotContain(header => string.Equals(header, Headers.TenantId, StringComparison.OrdinalIgnoreCase));
    }
}
