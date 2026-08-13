// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

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

    /// <summary>The claim used to resolve a caller's tenant.</summary>
    public const string TenantClaim = "urn:cratis:security-spec:tenant";

    /// <summary>The source identifier mapped to <see cref="TenantId"/>.</summary>
    public const string TenantSourceIdentifier = "security-spec-tenant";

    /// <summary>A path that requires a session, and therefore a verified caller.</summary>
    public const string ProtectedPath = "/private";

    /// <summary>A path the service explicitly declares anonymous.</summary>
    public const string AnonymousPath = "/public";

    /// <summary>A static asset path a browser fetches after the page, served by the service's frontend.</summary>
    public const string StaticAssetPath = "/assets/app.js";

    /// <summary>The body of the page a refused caller is served, so a spec can recognize it.</summary>
    public const string ForbiddenMarker = "forbidden-page";

    /// <summary>An application-owned cookie configured for deletion with the session.</summary>
    public const string AdditionalSessionCookie = "security-spec-session";

    /// <summary>A representative transient provider correlation cookie.</summary>
    public const string CorrelationCookie = $"{Cookies.CorrelationPrefix}security-spec";

    /// <summary>A representative transient provider nonce cookie.</summary>
    public const string NonceCookie = $"{Cookies.NoncePrefix}security-spec";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly bool _terminateOnIdentityDenial;

    /// <summary>
    /// Initializes a new instance of the <see cref="RequiredVerificationHarness"/> class.
    /// </summary>
    public RequiredVerificationHarness() : this(true)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RequiredVerificationHarness"/> class.
    /// </summary>
    /// <param name="terminateOnIdentityDenial">Whether denial terminates the local session.</param>
    internal RequiredVerificationHarness(bool terminateOnIdentityDenial)
    {
        _terminateOnIdentityDenial = terminateOnIdentityDenial;
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

    /// <summary>Makes the origin explicitly deny every caller.</summary>
    public void DenyEveryCaller() => Origin.IdentityResponse = () => Results.Json(new
    {
        isAuthenticated = true,
        isAuthorized = false,
        details = new { }
    });

    /// <summary>Makes the origin answer without an identity verdict.</summary>
    public void AnswerWithoutVerdict() => Origin.IdentityResponse = () => Results.Json(new { });

    /// <summary>Makes the origin answer with malformed JSON.</summary>
    public void AnswerWithMalformedJson() => Origin.IdentityResponse = () => Results.Text("{not-json", "application/json");

    /// <summary>Makes the origin answer with conflicting identity verdicts.</summary>
    public void AnswerWithConflictingVerdicts() => Origin.IdentityResponse = () => Results.Json(new
    {
        isAuthenticated = false,
        isAuthorized = true,
        details = new { displayName = "Contradictory Caller" }
    });

    /// <summary>
    /// Creates a client that surfaces redirects as responses rather than following them.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateSecurityClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <summary>
    /// Builds a request carrying a real protected ASP.NET Core cookie ticket.
    /// </summary>
    /// <param name="path">The path to request.</param>
    /// <param name="includeTenant">Whether the ticket carries the configured tenant claim.</param>
    /// <param name="passTenancyWithoutTenant">
    /// Whether to present a pending-registration cookie so the tenant-less request reaches identity
    /// verification.
    /// </param>
    /// <returns>The request and the authentication-cookie chunk names it carries.</returns>
    public SessionRequest AuthenticatedRequest(
        string path,
        bool includeTenant = true,
        bool passTenancyWithoutTenant = false)
    {
        var options = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var user = Guid.NewGuid().ToString("N");
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user),
            new("oid", user),
            new(ClaimTypes.Name, user),
            new(
                "urn:cratis:security-spec:padding",
                string.Join('-', Enumerable.Range(0, 150).Select(_ => Guid.NewGuid().ToString("N"))))
        };
        if (includeTenant)
        {
            claims.Add(new Claim(TenantClaim, TenantSourceIdentifier));
        }

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
        var ticket = new AuthenticationTicket(
            principal,
            CookieAuthenticationDefaults.AuthenticationScheme);
        var protectedTicket = options.TicketDataFormat.Protect(ticket);
        var cookieContext = new DefaultHttpContext();
        cookieContext.Request.Scheme = "https";
        options.CookieManager.AppendResponseCookie(
            cookieContext,
            options.Cookie.Name!,
            protectedTicket,
            options.Cookie.Build(cookieContext));

        var authenticationCookies = cookieContext.Response.Headers.SetCookie
            .Select(_ => _.Split(';', 2)[0])
            .ToArray();
        var presented = authenticationCookies
            .Concat(
            [
                $"{CorrelationCookie}=correlation",
                $"{NonceCookie}=nonce",
                $"{AdditionalSessionCookie}=additional"
            ])
            .ToList();
        if (passTenancyWithoutTenant)
        {
            presented.Add($"{Cookies.Registration}=pending");
        }

        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", presented));

        return new SessionRequest(
            request,
            authenticationCookies
                .Select(_ => _[.._.IndexOf('=', StringComparison.Ordinal)])
                .ToArray());
    }

    /// <summary>Gets whether a response expires the named cookie.</summary>
    /// <param name="response">The response to inspect.</param>
    /// <param name="name">The exact cookie name.</param>
    /// <returns><see langword="true"/> when the response carries an expiry for the cookie.</returns>
    public static bool Deletes(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues("Set-Cookie", out var values)
        && values.Any(_ =>
            _.StartsWith($"{name}=;", StringComparison.Ordinal)
            && _.Contains("expires=", StringComparison.OrdinalIgnoreCase));

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
                [$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:0"] = AnonymousPath,

                [$"{C.AuthProxy.SectionKey}:Session:IdentityResultCacheDuration"] = "00:00:00",
                [$"{C.AuthProxy.SectionKey}:Session:TerminateOnIdentityDenial"] = _terminateOnIdentityDenial.ToString(),
                [$"{C.AuthProxy.SectionKey}:Logout:AdditionalCookies:0:Name"] = AdditionalSessionCookie,

                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Claim),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:ClaimType"] = TenantClaim,
                [$"{C.AuthProxy.SectionKey}:Tenants:{TenantId}:SourceIdentifiers:0"] = TenantSourceIdentifier,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
            }));
    }
}
