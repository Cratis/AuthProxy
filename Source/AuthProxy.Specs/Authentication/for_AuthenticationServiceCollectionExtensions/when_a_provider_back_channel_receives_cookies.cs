// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_a_provider_back_channel_receives_cookies : Specification
{
    [Theory]
    [InlineData("oidc")]
    [InlineData("oauth")]
    [InlineData("jwt")]
    public async Task should_not_store_or_replay_response_cookies(string protocol)
    {
        var cookies = new List<string>();
        var serverBuilder = WebApplication.CreateBuilder();
        serverBuilder.Logging.ClearProviders();
        serverBuilder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
        await using var server = serverBuilder.Build();
        server.MapGet("/provider", (HttpContext context) =>
        {
            cookies.Add(context.Request.Headers.Cookie.ToString());
            context.Response.Cookies.Append("provider-session", "synthetic-session");
            return Results.Ok();
        });
        await server.StartAsync(TestContext.Current.CancellationToken);

        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "oidc",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://issuer.example",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "synthetic-client",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = "oauth",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "synthetic-client",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret"] = "synthetic-secret",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "https://issuer.example/authorize",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "https://issuer.example/token",
            [$"{C.Authentication.SectionKey}:JwtBearer:Authority"] = "https://issuer.example",
            [$"{C.Authentication.SectionKey}:JwtBearer:Audience"] = "synthetic-audience"
        });
        builder.AddIngressAuthentication();
        await using var services = builder.Services.BuildServiceProvider();
        using var client = protocol switch
        {
            "oidc" => services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("oidc").Backchannel,
            "oauth" => services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get("oauth").Backchannel,
            _ => services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme).Backchannel
        };
        var endpoint = $"{server.Urls.Single()}/provider";
        using var first = await client.GetAsync(endpoint, TestContext.Current.CancellationToken);
        using var second = await client.GetAsync(endpoint, TestContext.Current.CancellationToken);

        first.IsSuccessStatusCode.ShouldBeTrue();
        second.IsSuccessStatusCode.ShouldBeTrue();
        cookies.ShouldEqual(new[] { string.Empty, string.Empty });
        await server.StopAsync(TestContext.Current.CancellationToken);
    }
}
