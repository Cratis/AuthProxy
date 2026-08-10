// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy whose one service answers <c>/.cratis/me</c> with an authorization verdict, in front
/// of a real recording origin whose answer a spec controls.
/// </summary>
/// <remarks>
/// A third harness rather than a setting on the shared one, because the shared one is the deployment every
/// other security spec reasons about — an identity endpoint that enriches — and requiring verification of it
/// would change the premise of all of them. The question here is the opposite one: given a deployment that
/// treats the answer as a decision, what happens when the answer never arrives.
/// <para>
/// Deliberately end to end. A unit spec can establish that the resolver refuses; only a running proxy
/// establishes that the refusal is on the request path for everything a browser fetches — the page, and
/// every static asset it pulls afterwards — and that nothing reaches the backend on the way.
/// </para>
/// <para>
/// Result caching is switched off so consecutive requests in one spec are genuinely re-verified rather than
/// answered from the previous one, and the re-validation interval is left at its default so the sealed
/// record behaves as a deployment would see it.
/// </para>
/// </remarks>
public class RequiredVerificationHarness : WebApplicationFactory<Program>
{
    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "33333333-3333-3333-3333-333333333333";

    /// <summary>A path that requires a session, and therefore a verified caller.</summary>
    public const string ProtectedPath = "/private";

    /// <summary>A static asset path a browser fetches after the page, served by the service's frontend.</summary>
    public const string StaticAssetPath = "/assets/app.js";

    /// <summary>The body of the page a refused caller is served, so a spec can recognize it.</summary>
    public const string ForbiddenMarker = "forbidden-page";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="RequiredVerificationHarness"/> class.
    /// </summary>
    public RequiredVerificationHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.Forbidden), $"<html><body>{ForbiddenMarker}</body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the origin AuthProxy forwards to, and the record of what reached it.
    /// </summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Makes the origin answer the identity endpoint with an unambiguous positive verdict.
    /// </summary>
    public void VerifyEveryCaller() =>
        Origin.IdentityResponse = () => Results.Json(new
        {
            isAuthenticated = true,
            isAuthorized = true,
            details = new { displayName = "Verified Caller" }
        });

    /// <summary>
    /// Makes the origin's identity endpoint unavailable, the way an outage or a rollout would.
    /// </summary>
    public void FailEveryVerification() => Origin.IdentityResponse = () => Results.StatusCode(StatusCodes.Status503ServiceUnavailable);

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
                [$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.Required),
                [$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerificationTimeout"] = "00:00:05",

                [$"{C.AuthProxy.SectionKey}:Session:IdentityResultCacheDuration"] = "00:00:00",

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
