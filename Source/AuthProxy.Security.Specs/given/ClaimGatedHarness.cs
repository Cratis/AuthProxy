// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy that requires a claim of everyone before forwarding anything, in front of a real
/// recording origin.
/// </summary>
/// <remarks>
/// A second harness rather than a setting on the shared one, because the shared one is the deployment
/// every other security spec reasons about — "authenticated is enough" — and gating it would change the
/// premise of all of them. The question here is different: given that a deployment does gate, what still
/// gets through.
/// <para>
/// It is deliberately end to end. The unit specs establish what the policy decides; only a running proxy
/// establishes that the decision is on the request path at all — ahead of tenancy, of the identity call to
/// the backend, and of the reverse proxy. A middleware that was never wired in would pass every unit spec
/// and gate nothing.
/// </para>
/// </remarks>
public class ClaimGatedHarness : WebApplicationFactory<Program>
{
    /// <summary>The claim this deployment requires.</summary>
    public const string RequiredClaim = "urn:github:organization";

    /// <summary>The one value of that claim this deployment accepts.</summary>
    public const string RequiredValue = "Cratis";

    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "22222222-2222-2222-2222-222222222222";

    /// <summary>The one path this deployment declares anonymous.</summary>
    public const string AnonymousPath = "/public";

    /// <summary>A path that is not anonymous and therefore passes the gate.</summary>
    public const string ProtectedPath = "/private";

    /// <summary>The body of the page a refused caller is served, so a spec can recognize it.</summary>
    public const string NotAuthorizedMarker = "not-authorized-page";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="ClaimGatedHarness"/> class.
    /// </summary>
    public ClaimGatedHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");
        File.WriteAllText(
            Path.Combine(_pagesPath, WellKnownPageNames.NotAuthorized),
            $"<html><body>{NotAuthorizedMarker}<a href=\"{WellKnownPaths.Logout}?redirect=/\">Sign out</a></body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the origin AuthProxy forwards to, and the record of what reached it.
    /// </summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Builds a request from an authenticated caller carrying the required claim.
    /// </summary>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage Qualified(string pathAndQuery) =>
        WithClaims(pathAndQuery, $"{RequiredClaim}={RequiredValue}");

    /// <summary>
    /// Builds a request from an authenticated caller carrying the claim with an unaccepted value — the
    /// account that completes sign-in at a public identity provider and should still get nowhere.
    /// </summary>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage Unqualified(string pathAndQuery) =>
        WithClaims(pathAndQuery, $"{RequiredClaim}=some-other-org");

    /// <summary>
    /// Builds a request from an authenticated caller carrying the given claims.
    /// </summary>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <param name="claims">The claims, as <c>type=value</c> pairs separated by semicolons.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage WithClaims(string pathAndQuery, string claims)
    {
        var request = SecurityHarness.Authenticated(HttpMethod.Get, pathAndQuery, SecurityHarness.UniqueUser("claim-gate"));
        request.Headers.TryAddWithoutValidation(HeaderAuthenticationHandler.ClaimsHeader, claims);

        return request;
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

        Origin.DisposeAsync().AsTask().GetAwaiter().GetResult();

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
                [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:0"] = AnonymousPath,

                [$"{C.Authorization.SectionKey}:RequiredClaims:0:Claim"] = RequiredClaim,
                [$"{C.Authorization.SectionKey}:RequiredClaims:0:AnyOf:0"] = RequiredValue,

                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

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
