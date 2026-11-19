// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_denied_paths_are_configured;

/// <summary>
/// Runs the production Program with a public-host refusal boundary and observable authentication.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    /// <summary>
    /// Gets the authentication call counter.
    /// </summary>
    public AuthenticationCalls Calls { get; } = new();

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Test").ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Ingress.SectionKey}:DeniedPathPrefixes:0"] = "/internal/",
            [$"{C.Ingress.SectionKey}:DeniedPathPrefixes:1"] = "/.auth/",
            [$"{C.Ingress.SectionKey}:DeniedPathPrefixes:2"] = "/assets/",
            [$"{C.Ingress.SectionKey}:DeniedPathPrefixes:3"] = "/grpc/",
        })).ConfigureTestServices(services =>
        {
            services.AddSingleton(Calls);
            services.AddAuthentication(TestAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, _ => { });
        });
    }

    /// <summary>
    /// Counts requests reaching authentication.
    /// </summary>
    public class AuthenticationCalls
    {
        /// <summary>
        /// Gets or sets the call count.
        /// </summary>
        public int Count { get; set; }
    }

    /// <summary>
    /// Leaves requests unauthenticated, recording whether the guard let them through.
    /// </summary>
    /// <param name="options">Authentication options.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="calls">The call counter.</param>
    public class TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder,
        AuthenticationCalls calls) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string Scheme = "DeniedPathTest";

        /// <inheritdoc/>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            calls.Count++;
            return Task.FromResult(AuthenticateResult.NoResult());
        }
    }
}
