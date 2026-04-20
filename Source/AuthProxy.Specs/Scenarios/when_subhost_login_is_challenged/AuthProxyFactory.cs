// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_subhost_login_is_challenged;

/// <summary>
/// WebApplicationFactory that configures a single OAuth provider and SubHost tenant resolution
/// so the challenge state can be validated end-to-end.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    /// <summary>The parent host configured for SubHost tenant resolution.</summary>
    public const string ParentHost = "cratis.studio";

    /// <summary>The provider scheme derived from configured provider name.</summary>
    public const string ProviderScheme = "github";

    /// <summary>Gets the last scheme used in a captured challenge call.</summary>
    public string? CapturedScheme => _captureService.CapturedScheme;

    /// <summary>Gets the last authentication properties used in a captured challenge call.</summary>
    public AuthenticationProperties? CapturedProperties => _captureService.CapturedProperties;

    readonly ChallengeCaptureAuthenticationService _captureService = new();

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.SubHost),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:ParentHost"] = ParentHost,

                [$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = "GitHub",
                [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "https://github.com/login/oauth/authorize",
                [$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "https://github.com/login/oauth/access_token",
                [$"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint"] = "https://api.github.com/user",
                [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "client-id",
                [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret"] = "client-secret",
                [$"{C.Authentication.SectionKey}:OAuthProviders:0:Scopes:0"] = "read:user",
            });
        });

        builder.ConfigureTestServices(services => services.AddSingleton<IAuthenticationService>(_captureService));
    }

    /// <summary>Creates a test HTTP client that does not follow redirects.</summary>
    /// <returns>A configured <see cref="HttpClient"/> that does not follow redirects.</returns>
    public HttpClient CreateTestClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    sealed class ChallengeCaptureAuthenticationService : IAuthenticationService
    {
        public string? CapturedScheme { get; private set; }

        public AuthenticationProperties? CapturedProperties { get; private set; }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            CapturedScheme = scheme;
            CapturedProperties = properties;
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = "https://example.test/oauth/authorize";
            return Task.CompletedTask;
        }

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            Task.CompletedTask;
    }
}