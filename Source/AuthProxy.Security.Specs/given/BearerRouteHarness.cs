// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy with one bearer route, in front of a recording origin, trusting a stub issuer.
/// </summary>
/// <remarks>
/// Configured the way Direct would be: <c language="text">/mcp</c> accepts access tokens for the <c language="text">direct-api</c>
/// audience from the issuer, requires <c language="text">direct:read</c>, and forwards the GitHub id and login the browser
/// sessions of the same deployment carry. Everything else — <c language="text">/api</c>, the frontend — stays on the
/// browser-session model, where a caller becomes authenticated by sending
/// <see cref="SecurityHarness.AuthenticatedUserHeader"/>.
/// </remarks>
public class BearerRouteHarness : WebApplicationFactory<Program>
{
    /// <summary>The bearer route's path prefix.</summary>
    public const string RoutePrefix = "/mcp";

    /// <summary>The audience the route accepts.</summary>
    public const string Audience = "direct-api";

    /// <summary>The scope the route requires.</summary>
    public const string RequiredScope = "direct:read";

    /// <summary>The protected-resource metadata URL the route names in its challenges.</summary>
    public const string ResourceMetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/mcp";

    /// <summary>The path of <see cref="ResourceMetadataUrl"/>.</summary>
    public const string ResourceMetadataPath = "/.well-known/oauth-protected-resource/mcp";

    /// <summary>The Cratis account id the tokens carry as <c language="text">sub</c>.</summary>
    public const string AccountId = "7d4f9a52-1c1e-4bb8-9d0b-0f5c7b3e2a10";

    /// <summary>The tenant the tokens carry as <c language="text">tid</c>.</summary>
    public const string TenantId = "22222222-2222-2222-2222-222222222222";

    /// <summary>The GitHub id the tokens carry.</summary>
    public const string GitHubId = "134365";

    /// <summary>The GitHub login the tokens carry.</summary>
    public const string GitHubLogin = "einari";

    /// <summary>The client the tokens were issued to.</summary>
    public const string ClientId = "cratis-cli";

    /// <summary>The tenant a browser session resolves to.</summary>
    public const string SessionTenantId = "11111111-1111-1111-1111-111111111111";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="BearerRouteHarness"/> class.
    /// </summary>
    public BearerRouteHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "select-provider.html"), "<html><body>Select Provider</body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "forbidden.html"), "<html><body>Forbidden</body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
        Issuer = StubIssuer.Start().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the origin AuthProxy forwards to, and the record of what reached it.
    /// </summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Gets the authorization server whose tokens the bearer route accepts.
    /// </summary>
    public StubIssuer Issuer { get; }

    /// <summary>
    /// Builds a request carrying a bearer token.
    /// </summary>
    /// <param name="method">The HTTP method.</param>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <param name="token">The token.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage WithToken(HttpMethod method, string pathAndQuery, string token)
    {
        var request = new HttpRequestMessage(method, pathAndQuery);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    /// <summary>
    /// Creates a client that neither follows redirects nor carries cookies between requests.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateBearerClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        Origin.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Issuer.DisposeAsync().AsTask().GetAwaiter().GetResult();

        if (Directory.Exists(_pagesPath))
        {
            Directory.Delete(_pagesPath, recursive: true);
        }
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        const string route = $"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0";

        builder
            .UseEnvironment("Production")
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = Origin.BaseUrl,

                [$"{route}:PathPrefix"] = RoutePrefix,
                [$"{route}:Issuers:0:Issuer"] = Issuer.Issuer,
                [$"{route}:Audiences:0"] = Audience,
                [$"{route}:RequiredScopes:0"] = RequiredScope,
                [$"{route}:ResourceMetadataUrl"] = ResourceMetadataUrl,
                [$"{route}:IdentityProvider"] = "github",
                [$"{route}:ClaimMappings:sub"] = "github_id",
                [$"{route}:ClaimMappings:preferred_username"] = "github_login",

                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = SessionTenantId,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
            }))
            .ConfigureTestServices(services => services
                .AddAuthentication(HeaderAuthenticationHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(
                    HeaderAuthenticationHandler.Scheme,
                    _ => { }));
    }
}
