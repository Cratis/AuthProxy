// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy in front of a service whose backend receives the signed-in user's access token, with separate
/// recording origins for the backend and the frontend.
/// </summary>
/// <remarks>
/// The session cookie and the identity provider are stood in for: a request carrying <see cref="TokenSessionHeader"/>
/// is treated as a cookie session holding that token session, and the stand-in <see cref="IUserAccessTokens"/> mints
/// a token naming it, or refuses for <see cref="RejectedSession"/>. What is under test is the request path: that the
/// forwarding stage runs in the proxy pipeline at all, that it replaces what the caller sent, and that it refuses
/// rather than forwards when no token is available.
/// </remarks>
public class AccessTokenForwardingHarness : WebApplicationFactory<Program>
{
    /// <summary>The request header naming the token session of a simulated cookie session.</summary>
    public const string TokenSessionHeader = "X-Security-Spec-Token-Session";

    /// <summary>A token session for which no token can be obtained.</summary>
    public const string RejectedSession = "rejected-session";

    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "44444444-4444-4444-4444-444444444444";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenForwardingHarness"/> class.
    /// </summary>
    public AccessTokenForwardingHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");

        Backend = RecordingBackend.Start().GetAwaiter().GetResult();
        Frontend = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>Gets the origin of the service's backend.</summary>
    public RecordingBackend Backend { get; }

    /// <summary>Gets the origin of the service's frontend.</summary>
    public RecordingBackend Frontend { get; }

    /// <summary>
    /// Gets the token the stand-in provider issues for a token session.
    /// </summary>
    /// <param name="session">The token session.</param>
    /// <returns>The token.</returns>
    public static string TokenFor(string session) => $"user-token-for-{session}";

    /// <summary>
    /// Builds a request from a signed-in cookie session.
    /// </summary>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <param name="session">The token session the cookie session holds.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage FromSession(string pathAndQuery, string session)
    {
        var request = SecurityHarness.Authenticated(HttpMethod.Get, pathAndQuery, SecurityHarness.UniqueUser("token-forwarding"));
        request.Headers.TryAddWithoutValidation(TokenSessionHeader, session);
        return request;
    }

    /// <summary>
    /// Forgets what both origins received.
    /// </summary>
    public void ClearOrigins()
    {
        Backend.Clear();
        Frontend.Clear();
    }

    /// <summary>
    /// Creates a client that surfaces redirects as responses rather than following them.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateSecurityClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        Backend.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Frontend.DisposeAsync().AsTask().GetAwaiter().GetResult();

        if (Directory.Exists(_pagesPath))
        {
            Directory.Delete(_pagesPath, recursive: true);
        }
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder
            .UseEnvironment("Production")
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:reporting:Backend:BaseUrl"] = Backend.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:reporting:Frontend:BaseUrl"] = Frontend.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:reporting:ResolveIdentityDetails"] = "false",
                [$"{C.AuthProxy.SectionKey}:Services:reporting:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
                [$"{C.AuthProxy.SectionKey}:Services:reporting:AccessToken:Scopes:0"] = "api://reporting/access_as_user",

                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
            }))
            .ConfigureTestServices(services =>
            {
                services
                    .AddAuthentication(HeaderAuthenticationHandler.Scheme)
                    .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(HeaderAuthenticationHandler.Scheme, _ => { });
                services.AddSingleton<IUserAccessTokens, StandInUserAccessTokens>();
                services.AddSingleton<IStartupFilter, SimulatedCookieSessionStartupFilter>();
            });
    }

    sealed class StandInUserAccessTokens : IUserAccessTokens
    {
        public Task<UserAccessTokenResult> GetFor(string sessionId, C.ServiceAccessToken accessToken, CancellationToken cancellationToken) =>
            Task.FromResult(sessionId == RejectedSession
                ? UserAccessTokenResult.Failed(UserAccessTokenFailure.RefreshTokenRejected)
                : UserAccessTokenResult.Success(TokenFor(sessionId)));
    }

    sealed class SimulatedCookieSessionStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
            app =>
            {
                app.Use(async (context, proceed) =>
                {
                    var session = context.Request.Headers[TokenSessionHeader].ToString();
                    context.Request.Headers.Remove(TokenSessionHeader);
                    if (session.Length > 0)
                    {
                        context.Items[Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] = CookieAuthenticationDefaults.AuthenticationScheme;
                        context.Items["Cratis.AuthProxy.TokenSession"] = session;
                    }

                    await proceed();
                });

                next(app);
            };
    }
}
