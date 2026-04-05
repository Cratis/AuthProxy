// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using Cratis.Ingress.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;

namespace Cratis.Ingress.Authentication;

/// <summary>
/// Extension methods for registering authentication services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Registers cookie authentication, all configured OIDC providers, all configured OAuth providers,
    /// and (optionally) JWT Bearer for machine-to-machine flows.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddIngressAuthentication(this WebApplicationBuilder builder)
    {
        var authBuilder = builder.Services
            .AddAuthentication(options => options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, ConfigureCookieOptions);

        var authConfig = builder.Configuration
            .GetSection("Authentication")
            .Get<AuthenticationConfig>() ?? new AuthenticationConfig();

        RegisterOidcProviders(authBuilder, authConfig.OidcProviders);
        RegisterOAuthProviders(authBuilder, authConfig.OAuthProviders);

        var jwtSection = builder.Configuration.GetSection("Authentication:JwtBearer");
        if (jwtSection.Exists())
        {
            authBuilder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, jwtSection.Bind);
        }

        builder.Services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build());

        return builder;
    }

    static void ConfigureCookieOptions(CookieAuthenticationOptions options)
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

        // Redirect unauthenticated users to the provider selection page (multiple providers)
        // or directly to the single provider login endpoint.
        options.Events.OnRedirectToLogin = ctx =>
        {
            var authConfig = ctx.HttpContext.RequestServices
                .GetRequiredService<IOptionsMonitor<AuthenticationConfig>>()
                .CurrentValue;

            var returnUrl = ctx.Request.Path + ctx.Request.QueryString;

            if (authConfig.TotalProviderCount > 1)
            {
                ctx.Response.Redirect($"{WellKnownPaths.LoginPage}?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return Task.CompletedTask;
            }

            if (authConfig.OidcProviders.Count == 1)
            {
                var scheme = OidcProviderScheme.FromName(authConfig.OidcProviders[0].Name);
                ctx.Response.Redirect($"{WellKnownPaths.LoginPrefix}/{scheme}?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return Task.CompletedTask;
            }

            if (authConfig.OAuthProviders.Count == 1)
            {
                var scheme = OidcProviderScheme.FromName(authConfig.OAuthProviders[0].Name);
                ctx.Response.Redirect($"{WellKnownPaths.LoginPrefix}/{scheme}?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return Task.CompletedTask;
            }

            ctx.Response.Redirect(ctx.RedirectUri);
            return Task.CompletedTask;
        };
    }

    static void RegisterOidcProviders(AuthenticationBuilder authBuilder, IList<OidcProviderConfig> providers)
    {
        foreach (var provider in providers)
        {
            var scheme = OidcProviderScheme.FromName(provider.Name);
            authBuilder.AddOpenIdConnect(scheme, options =>
            {
                options.Authority = provider.Authority;
                options.ClientId = provider.ClientId;
                options.ClientSecret = provider.ClientSecret;
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");

                foreach (var scope in provider.Scopes)
                {
                    options.Scope.Add(scope);
                }

                options.CallbackPath = $"/signin-{scheme}";
            });
        }
    }

    static void RegisterOAuthProviders(AuthenticationBuilder authBuilder, IList<OAuthProviderConfig> providers)
    {
        foreach (var provider in providers)
        {
            var scheme = OidcProviderScheme.FromName(provider.Name);
            var capturedProvider = provider;

            authBuilder.AddOAuth(scheme, options =>
            {
                options.AuthorizationEndpoint = capturedProvider.AuthorizationEndpoint;
                options.TokenEndpoint = capturedProvider.TokenEndpoint;
                options.UserInformationEndpoint = capturedProvider.UserInformationEndpoint;
                options.ClientId = capturedProvider.ClientId;
                options.ClientSecret = capturedProvider.ClientSecret;
                options.CallbackPath = $"/signin-{scheme}";
                options.SaveTokens = true;

                foreach (var scope in capturedProvider.Scopes)
                {
                    options.Scope.Add(scope);
                }

                foreach (var mapping in capturedProvider.ClaimMappings)
                {
                    options.ClaimActions.MapJsonKey(mapping.Key, mapping.Value);
                }

                options.Events = new OAuthEvents
                {
                    OnCreatingTicket = async ctx =>
                    {
                        var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("Cratis-AuthProxy", "1.0"));

                        var response = await ctx.Backchannel.SendAsync(request, ctx.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        using var user = JsonDocument.Parse(
                            await response.Content.ReadAsStringAsync(ctx.HttpContext.RequestAborted));
                        ctx.RunClaimActions(user.RootElement);
                    }
                };
            });
        }
    }
}

