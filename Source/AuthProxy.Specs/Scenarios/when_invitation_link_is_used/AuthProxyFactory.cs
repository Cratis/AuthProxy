// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Claims;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// WebApplicationFactory that wires up a test-friendly AuthProxy with:
/// - An in-process RSA key pair for invite token signing/validation.
/// - A test authentication handler so tests can control whether requests appear authenticated.
/// - Intercepted HTTP calls for the exchange endpoint and identity backend.
/// - A fixed single-tenant configuration so <see cref="TenancyMiddleware"/> always resolves.
/// </summary>
public class AuthProxyFactory : WebApplicationFactory<Program>
{
    public const string ExchangeUrl = "http://exchange.test/invites/exchange";
    public const string IdentityBackendBaseUrl = "http://identity.test/";
    public const string LobbyUrl = "http://lobby.test/";
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    public (RsaSecurityKey PrivateKey, string PublicKeyPem) InviteKeyPair { get; } =
        TokenFixture.GenerateKeyPair();

    public int ExchangeCallCount => _exchangeCallCount;
    public int IdentityCallCount => _identityCallCount;

    int _exchangeCallCount;
    int _identityCallCount;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Invite token validation
                [$"{C.AuthProxy.SectionKey}:Invite:PublicKeyPem"] = InviteKeyPair.PublicKeyPem,
                [$"{C.AuthProxy.SectionKey}:Invite:ExchangeUrl"] = ExchangeUrl,
                [$"{C.AuthProxy.SectionKey}:Invite:Lobby:Frontend:BaseUrl"] = LobbyUrl,

                // Single identity backend
                [$"{C.AuthProxy.SectionKey}:Services:test:Backend:BaseUrl"] = IdentityBackendBaseUrl,

                // Tenant resolution: always resolve to fixed tenant ID
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

                // Static webroot and pages paths (use temp directories)
                [$"{C.AuthProxy.SectionKey}:PagesPath"] = Path.GetTempPath(),
            });
        });

        builder.ConfigureTestServices(services =>
        {
            // Replace authentication with a test scheme that the test controls via a request header.
            services.AddAuthentication(TestAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, _ => { });

            // Replace the HTTP client factory with one that intercepts all outbound calls.
            services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(
                url =>
                {
                    if (url.StartsWith(ExchangeUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        Interlocked.Increment(ref _exchangeCallCount);
                        return new HttpResponseMessage(HttpStatusCode.OK);
                    }

                    if (url.StartsWith(IdentityBackendBaseUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        Interlocked.Increment(ref _identityCallCount);
                        return new HttpResponseMessage(HttpStatusCode.OK)
                        {
                            Content = new StringContent(/*lang=json,strict*/ "{\"displayName\":\"Test User\"}")
                        };
                    }

                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                }));
        });
    }

    /// <summary>
    /// Creates an <see cref="HttpClient"/> that:
    /// - Does not follow redirects (so tests can inspect 302 responses).
    /// - Optionally appears authenticated (sets the <c>X-Test-Auth</c> header on every request).
    /// - Optionally carries an invite token cookie.
    /// </summary>
    public HttpClient CreateTestClient(bool authenticated = false, string? inviteTokenCookie = null)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        if (authenticated)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.AuthHeader, "true");
        }

        if (!string.IsNullOrEmpty(inviteTokenCookie))
        {
            client.DefaultRequestHeaders.Add("Cookie", $"{Cookies.InviteToken}={inviteTokenCookie}");
        }

        return client;
    }

    /// <summary>Authentication handler that authenticates a request when the X-Test-Auth header is present.</summary>
    public class TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string Scheme = "TestScheme";
        public const string AuthHeader = "X-Test-Auth";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(AuthHeader))
                return Task.FromResult(AuthenticateResult.NoResult());

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, "test-user"),
                new Claim("sub", "test-user-id"),
                new Claim("oid", "test-user-id"),
            };
            var identity = new ClaimsIdentity(claims, Scheme);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }

    /// <summary>Minimal IHttpClientFactory that routes all calls through a single handler.</summary>
    sealed class TestHttpClientFactory(Func<string, HttpResponseMessage> handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new DispatchingHandler(handler)) { Timeout = TimeSpan.FromSeconds(10) };

        sealed class DispatchingHandler(Func<string, HttpResponseMessage> handler) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                Task.FromResult(handler(request.RequestUri?.ToString() ?? string.Empty));
        }
    }
}
