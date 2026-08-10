// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy in front of a real recording origin, shared by every security spec.
/// </summary>
/// <remarks>
/// Deliberately configured the way a real deployment is rather than the way that makes assertions easy: a
/// single service so the catch-all route exists and carries the authenticated-user policy, providers
/// configured so an unauthenticated caller is genuinely refused, a tenant that always resolves so a
/// refusal is attributable to the check under test, and one declared anonymous path so the one route that
/// legitimately skips authorization is present and can be probed for over-reach.
/// <para>
/// A caller becomes authenticated by sending <see cref="AuthenticatedUserHeader"/>, which stands in for
/// presenting a valid session cookie. Everything else about a request is left to the spec, because the
/// point of these specs is what an attacker can put on the wire.
/// </para>
/// </remarks>
public class SecurityHarness : WebApplicationFactory<Program>
{
    /// <summary>The header a spec sends to act as an authenticated user.</summary>
    public const string AuthenticatedUserHeader = "X-Security-Spec-User";

    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "11111111-1111-1111-1111-111111111111";

    /// <summary>The one path this deployment declares anonymous.</summary>
    public const string AnonymousPath = "/public";

    /// <summary>A path that is not anonymous and therefore requires a session.</summary>
    public const string ProtectedPath = "/private";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityHarness"/> class.
    /// </summary>
    /// <remarks>
    /// The origin has to exist before the proxy is configured, because its address is what the proxy is
    /// configured to forward to. A fixture constructor cannot be async, so the start is awaited here.
    /// </remarks>
    public SecurityHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "select-provider.html"), "<html><body>Select Provider</body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "forbidden.html"), "<html><body>Forbidden</body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the origin AuthProxy forwards to, and the record of what reached it.
    /// </summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Gets everything this deployment warned about, including at startup.
    /// </summary>
    /// <remarks>
    /// This deployment declares no trusted proxies, which is the compatibility fallback: it behaves exactly
    /// as AuthProxy always has, and the only thing that tells its operator so is a warning at startup.
    /// </remarks>
    public CapturedLogs Logs { get; } = new();

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

    /// <summary>
    /// Creates a client that surfaces redirects as responses rather than following them, and that sends
    /// only the cookies a spec puts on a request.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    /// <remarks>
    /// Redirects are not followed because the redirect itself is what the open-redirect specs are about.
    /// Cookies are not carried between requests because these specs are about what an attacker can present:
    /// a client that helpfully replayed a cookie AuthProxy had just issued would answer a different
    /// question — whether the legitimate flow works — and would quietly hand a spec the very sealed record
    /// it is trying to prove cannot be forged.
    /// </remarks>
    public HttpClient CreateSecurityClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <summary>
    /// Builds a request from an authenticated caller.
    /// </summary>
    /// <param name="method">The HTTP method.</param>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <param name="user">The user to act as. Defaults to a shared one.</param>
    /// <returns>A request carrying the harness's stand-in for a valid session.</returns>
    /// <remarks>
    /// A spec that needs to observe the identity resolution actually happening must pass a
    /// <paramref name="user"/> nobody else has used: the resolver holds a short-lived in-memory cache per
    /// user and tenant, so a shared identity would let an earlier spec's answer satisfy a later spec's
    /// request and the backend call being asserted on would never be made.
    /// </remarks>
    public static HttpRequestMessage Authenticated(HttpMethod method, string pathAndQuery, string? user = null)
    {
        var request = new HttpRequestMessage(method, pathAndQuery);
        request.Headers.TryAddWithoutValidation(AuthenticatedUserHeader, user ?? "security-spec-user");

        return request;
    }

    /// <summary>
    /// Creates a user identity no other spec shares.
    /// </summary>
    /// <param name="hint">A short label making the identity recognizable in a failure.</param>
    /// <returns>A unique user identity.</returns>
    public static string UniqueUser(string hint) => $"{hint}-{Guid.NewGuid():N}";

    /// <summary>
    /// Builds a request from an anonymous caller.
    /// </summary>
    /// <param name="method">The HTTP method.</param>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <returns>A request carrying no session.</returns>
    public static HttpRequestMessage Anonymous(HttpMethod method, string pathAndQuery) => new(method, pathAndQuery);

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder
            .UseEnvironment("Production")
            .ConfigureLogging(logging => logging.AddProvider(Logs))
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:0"] = AnonymousPath,

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
