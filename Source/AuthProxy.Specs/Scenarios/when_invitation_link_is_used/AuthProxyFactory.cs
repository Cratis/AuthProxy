// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    public (RsaSecurityKey PrivateKey, string PublicKeyPem) InviteKeyPair { get; } =
        TokenFixture.GenerateKeyPair();

    public int ExchangeCallCount => _exchangeCallCount;
    public int IdentityCallCount => _identityCallCount;
    public ClientPrincipal? CapturedIdentityPrincipal => _capturedIdentityPrincipal;

    int _exchangeCallCount;
    int _identityCallCount;
    ClientPrincipal? _capturedIdentityPrincipal;

    /// <summary>Initializes a new instance of the <see cref="AuthProxyFactory"/> class.</summary>
    public AuthProxyFactory()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-expired.html"), "<html><body><h1>Invitation Expired</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-invalid.html"), "<html><body><h1>Invitation Invalid</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-select-provider.html"), "<html><body><h1>Select Provider</h1></body></html>");
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_pagesPath))
            Directory.Delete(_pagesPath, recursive: true);
    }

    /// <summary>
    /// Override to supply additional in-memory configuration entries on top of the base configuration.
    /// </summary>
    /// <returns>Key/value pairs that are merged into the app configuration.</returns>
    protected virtual IEnumerable<KeyValuePair<string, string?>> GetAdditionalConfiguration() => [];

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            var entries = new Dictionary<string, string?>
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
                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,
            };
            config.AddInMemoryCollection(entries);
            config.AddInMemoryCollection(GetAdditionalConfiguration());
        });

        builder.ConfigureTestServices(services =>
        {
            // Replace authentication with a test scheme that the test controls via a request header.
            services.AddAuthentication(TestAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, _ => { });

            // Replace the HTTP client factory with one that intercepts all outbound calls.
            services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(
                request =>
                {
                    var url = request.RequestUri?.ToString() ?? string.Empty;

                    if (url.StartsWith(ExchangeUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        Interlocked.Increment(ref _exchangeCallCount);
                        return new HttpResponseMessage(HttpStatusCode.OK);
                    }

                    if (url.StartsWith(IdentityBackendBaseUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        Interlocked.Increment(ref _identityCallCount);
                        if (request.Headers.TryGetValues(Headers.Principal, out var principalValues))
                        {
                            ClientPrincipal.TryFromBase64(principalValues.First(), out var captured);
                            _capturedIdentityPrincipal = captured;
                        }
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
    /// <param name="authenticated">Whether the client should appear authenticated.</param>
    /// <param name="inviteTokenCookie">Optional invite token to send as a cookie.</param>
    /// <returns>A configured <see cref="HttpClient"/> that does not follow redirects.</returns>
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
    /// <param name="handler">The request dispatch function receiving the full outbound request.</param>
    sealed class TestHttpClientFactory(Func<HttpRequestMessage, HttpResponseMessage> handler) : IHttpClientFactory
    {
        /// <inheritdoc/>
        public HttpClient CreateClient(string name) =>
            new(new DispatchingHandler(handler)) { Timeout = TimeSpan.FromSeconds(10) };

        sealed class DispatchingHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                Task.FromResult(handler(request));
        }
    }
}
