// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_page_is_not_found;

/// <summary>
/// WebApplicationFactory that configures no services (no YARP routes) and no tenant resolution,
/// so that requests to unknown paths naturally result in 404 responses.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Test");

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(TestAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, _ => { });
        });
    }

    /// <summary>Creates a test HTTP client that does not follow redirects.</summary>
    /// <param name="authenticated">Whether the client should appear authenticated.</param>
    /// <returns>A configured <see cref="HttpClient"/> that does not follow redirects.</returns>
    public HttpClient CreateTestClient(bool authenticated = false)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (authenticated)
            client.DefaultRequestHeaders.Add(TestAuthHandler.AuthHeader, "true");
        return client;
    }

    /// <summary>Authentication handler that authenticates a request when the X-Test-Auth header is present.</summary>
    /// <param name="options">The options monitor for authentication scheme options.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    public class TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string Scheme = "TestScheme";
        public const string AuthHeader = "X-Test-Auth";

        /// <inheritdoc/>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(AuthHeader))
                return Task.FromResult(AuthenticateResult.NoResult());

            var claims = new[] { new Claim(ClaimTypes.Name, "test-user"), new Claim("sub", "test-user-id") };
            var identity = new ClaimsIdentity(claims, Scheme);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme)));
        }
    }
}
