// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
/// A running AuthProxy in front of two services, reached by host: one with the default handling of the caller's
/// Authorization header and one that forwards it, each with a recording origin.
/// </summary>
/// <remarks>
/// The session cookie is stood in for: a request carrying <see cref="SessionHeader"/> is treated as a cookie session.
/// </remarks>
public class UpstreamRequestsHarness : WebApplicationFactory<Program>
{
    /// <summary>The request header marking a simulated cookie session.</summary>
    public const string SessionHeader = "X-Security-Spec-Session";

    /// <summary>The host of the service with the default handling.</summary>
    public const string DefaultHost = "default.example.test";

    /// <summary>The host of the service that forwards the caller's Authorization header.</summary>
    public const string ForwardingHost = "forwarding.example.test";

    /// <summary>The path of the service that needs no sign-in.</summary>
    public const string AnonymousPath = "/hooks/inbound";

    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "44444444-4444-4444-4444-444444444444";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="UpstreamRequestsHarness"/> class.
    /// </summary>
    public UpstreamRequestsHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");

        Default = RecordingBackend.Start().GetAwaiter().GetResult();
        Forwarding = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>Gets the origin of the service with the default handling.</summary>
    public RecordingBackend Default { get; }

    /// <summary>Gets the origin of the service that forwards the caller's Authorization header.</summary>
    public RecordingBackend Forwarding { get; }

    /// <summary>
    /// Builds a request to a host, optionally from a signed-in cookie session.
    /// </summary>
    /// <param name="host">The host to request.</param>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <param name="signedIn">Whether the request comes from a cookie session.</param>
    /// <returns>The request, carrying an Authorization header, an application cookie and the proxy's own cookies.</returns>
    public static HttpRequestMessage Request(string host, string pathAndQuery, bool signedIn)
    {
        var request = signedIn
            ? SecurityHarness.Authenticated(HttpMethod.Get, pathAndQuery, SecurityHarness.UniqueUser("upstream"))
            : new HttpRequestMessage(HttpMethod.Get, pathAndQuery);
        if (signedIn)
        {
            request.Headers.TryAddWithoutValidation(SessionHeader, "session");
        }

        request.Headers.Host = host;
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer callers-own-token");
        request.Headers.TryAddWithoutValidation("Cookie", "theme=dark; .cratis-tenant=abc; .Cratis.AuthProxy.Auth.v2=secret; .cratis-identity=x");
        return request;
    }

    /// <summary>
    /// Forgets what both origins received.
    /// </summary>
    public void ClearOrigins()
    {
        Default.Clear();
        Forwarding.Clear();
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

        Default.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Forwarding.DisposeAsync().AsTask().GetAwaiter().GetResult();

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
                [$"{C.AuthProxy.SectionKey}:Services:plain:Hosts:0"] = DefaultHost,
                [$"{C.AuthProxy.SectionKey}:Services:plain:Backend:BaseUrl"] = Default.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:plain:Frontend:BaseUrl"] = Default.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:plain:ResolveIdentityDetails"] = "false",
                [$"{C.AuthProxy.SectionKey}:Services:plain:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
                [$"{C.AuthProxy.SectionKey}:Services:plain:AnonymousPaths:0"] = AnonymousPath,

                [$"{C.AuthProxy.SectionKey}:Services:forwarding:Hosts:0"] = ForwardingHost,
                [$"{C.AuthProxy.SectionKey}:Services:forwarding:Backend:BaseUrl"] = Forwarding.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:forwarding:Frontend:BaseUrl"] = Forwarding.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:forwarding:ResolveIdentityDetails"] = "false",
                [$"{C.AuthProxy.SectionKey}:Services:forwarding:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
                [$"{C.AuthProxy.SectionKey}:Services:forwarding:CallerAuthorizationHeader"] = nameof(C.CallerAuthorizationHeaderForwarding.Forward),

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
                services.AddSingleton<IStartupFilter, SimulatedCookieSessionStartupFilter>();
            });
    }

    sealed class SimulatedCookieSessionStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
            app =>
            {
                app.Use(async (context, proceed) =>
                {
                    if (context.Request.Headers.Remove(SessionHeader))
                    {
                        context.Items[Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] = CookieAuthenticationDefaults.AuthenticationScheme;
                    }

                    await proceed();
                });

                next(app);
            };
    }
}
