// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy in front of three services on three hosts under one parent domain, using the real cookie
/// session — the one place a spec can show that a session issued on one host is the session on every host.
/// </summary>
/// <remarks>
/// The sign-in itself is the one thing it stands in for: a real handshake needs an identity provider. A request to
/// <see cref="SignInPath"/> signs a caller in through the real cookie scheme, so the cookie it sets is exactly the
/// cookie a completed handshake would have set — same handler, same options, same events. Everything after that is
/// the production path.
/// </remarks>
public class SessionCookieHarness : WebApplicationFactory<Program>
{
    /// <summary>The parent domain the session cookie is scoped to when one is configured.</summary>
    public const string Domain = ".example.test";

    /// <summary>The host of the console service, which any signed-in caller may use.</summary>
    public const string ConsoleHost = "console.example.test";

    /// <summary>The host of the operations service, which requires <see cref="OperationsClaim"/>.</summary>
    public const string OperationsHost = "operations.example.test";

    /// <summary>The host of the chronicle service, which any signed-in caller may use.</summary>
    public const string ChronicleHost = "chronicle.example.test";

    /// <summary>The claim the operations service requires.</summary>
    public const string OperationsClaim = "urn:github:team";

    /// <summary>The value of <see cref="OperationsClaim"/> the operations service accepts.</summary>
    public const string OperationsClaimValue = "Cratis/operations";

    /// <summary>The path that signs a caller in through the real cookie scheme.</summary>
    public const string SignInPath = "/.security-spec/sign-in";

    /// <summary>The query key that gives the signed-in caller the operations claim.</summary>
    public const string OperationsQueryKey = "operations";

    /// <summary>The name of the OAuth provider the harness signs in through.</summary>
    public const string ProviderName = "TestIdp";

    /// <summary>The scheme of <see cref="ProviderName"/>.</summary>
    public const string ProviderScheme = "testidp";

    /// <summary>The address the provider's authorization endpoint answers on.</summary>
    public const string ProviderAuthorizationEndpoint = "http://idp.test/authorize";

    /// <summary>An origin a sign-out may return to that is not under <see cref="Domain"/>.</summary>
    public const string OutsideTheDomainOrigin = "http://marketing.other.test";

    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "33333333-3333-3333-3333-333333333333";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionCookieHarness"/> class.
    /// </summary>
    public SessionCookieHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");

        ConsoleOrigin = RecordingBackend.Start().GetAwaiter().GetResult();
        OperationsOrigin = RecordingBackend.Start().GetAwaiter().GetResult();
        ChronicleOrigin = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>Gets the origin of the console service.</summary>
    public RecordingBackend ConsoleOrigin { get; }

    /// <summary>Gets the origin of the operations service.</summary>
    public RecordingBackend OperationsOrigin { get; }

    /// <summary>Gets the origin of the chronicle service.</summary>
    public RecordingBackend ChronicleOrigin { get; }

    /// <summary>Gets the configured session cookie name.</summary>
    public virtual string CookieName => C.Session.DefaultCookieName;

    /// <summary>Gets the configured session cookie domain, or <see langword="null"/> for a host-only cookie.</summary>
    protected virtual string? CookieDomain => Domain;

    /// <summary>Gets the configured sign-in callback host, or <see langword="null"/> when every host runs its own handshake.</summary>
    protected virtual string? CallbackHost => null;

    /// <summary>
    /// Gets the value of every <c language="text">Set-Cookie</c> header of a response, in the order they were sent.
    /// </summary>
    /// <param name="response">The response to read.</param>
    /// <returns>The raw header values.</returns>
    public static IReadOnlyList<string> SetCookies(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values) ? [.. values] : [];

    /// <summary>
    /// Gets whether a <c language="text">Set-Cookie</c> value expires the named cookie.
    /// </summary>
    /// <param name="setCookie">The raw header value.</param>
    /// <param name="name">The cookie name.</param>
    /// <returns><see langword="true"/> when it is a deletion of the cookie.</returns>
    public static bool IsDeletionOf(string setCookie, string name) =>
        setCookie.StartsWith($"{name}=;", StringComparison.Ordinal)
        && setCookie.Contains("expires=", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gets whether a <c language="text">Set-Cookie</c> value sets the named cookie to a value.
    /// </summary>
    /// <param name="setCookie">The raw header value.</param>
    /// <param name="name">The cookie name.</param>
    /// <returns><see langword="true"/> when it sets the cookie.</returns>
    public static bool IsSettingOf(string setCookie, string name) =>
        setCookie.StartsWith($"{name}=", StringComparison.Ordinal) && !IsDeletionOf(setCookie, name);

    /// <summary>
    /// Gets whether a <c language="text">Set-Cookie</c> value carries a <c language="text">Domain</c> attribute.
    /// </summary>
    /// <param name="setCookie">The raw header value.</param>
    /// <returns><see langword="true"/> when the cookie is scoped to a domain.</returns>
    public static bool HasDomain(string setCookie) => setCookie.Contains("domain=", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Builds a request for a host, optionally carrying cookies.
    /// </summary>
    /// <param name="host">The host to request.</param>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <param name="cookies">The <c language="text">name=value</c> pairs to send, each as its own pair of the one header.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage Request(string host, string pathAndQuery, params string[] cookies)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, pathAndQuery);
        request.Headers.Host = host;
        if (cookies.Length > 0)
        {
            request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies));
        }

        return request;
    }

    /// <summary>
    /// Signs a caller in on a host and returns the response, whose <c language="text">Set-Cookie</c> headers are the session.
    /// </summary>
    /// <param name="client">The client to use.</param>
    /// <param name="host">The host to sign in on.</param>
    /// <param name="withOperationsClaim">Whether the caller carries the claim the operations service requires.</param>
    /// <param name="cookies">Cookies the browser already holds.</param>
    /// <returns>The sign-in response.</returns>
    public Task<HttpResponseMessage> SignIn(HttpClient client, string host, bool withOperationsClaim = false, params string[] cookies) =>
        client.SendAsync(Request(host, $"{SignInPath}?{OperationsQueryKey}={withOperationsClaim}", cookies));

    /// <summary>
    /// Takes the reusable <c language="text">name=value</c> pairs a response set, skipping deletions.
    /// </summary>
    /// <param name="response">The response to read.</param>
    /// <returns>The cookie pairs, ready for a request.</returns>
    public static string[] SessionFrom(HttpResponseMessage response) =>
        [.. SetCookies(response)
            .Where(_ => !_.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase))
            .Select(_ => _.Split(';')[0])];

    /// <summary>
    /// Forgets what every origin received.
    /// </summary>
    public void ClearOrigins()
    {
        ConsoleOrigin.Clear();
        OperationsOrigin.Clear();
        ChronicleOrigin.Clear();
    }

    /// <summary>
    /// Creates a client that surfaces redirects as responses rather than following them and keeps no cookies of its own.
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

        ConsoleOrigin.DisposeAsync().AsTask().GetAwaiter().GetResult();
        OperationsOrigin.DisposeAsync().AsTask().GetAwaiter().GetResult();
        ChronicleOrigin.DisposeAsync().AsTask().GetAwaiter().GetResult();

        if (Directory.Exists(_pagesPath))
        {
            Directory.Delete(_pagesPath, recursive: true);
        }
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var settings = new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:console:Hosts:0"] = ConsoleHost,
            [$"{C.AuthProxy.SectionKey}:Services:console:ResolveIdentityDetails"] = "false",
            [$"{C.AuthProxy.SectionKey}:Services:console:Backend:BaseUrl"] = ConsoleOrigin.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:console:Frontend:BaseUrl"] = ConsoleOrigin.BaseUrl,

            [$"{C.AuthProxy.SectionKey}:Services:operations:Hosts:0"] = OperationsHost,
            [$"{C.AuthProxy.SectionKey}:Services:operations:ResolveIdentityDetails"] = "false",
            [$"{C.AuthProxy.SectionKey}:Services:operations:Backend:BaseUrl"] = OperationsOrigin.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:operations:Frontend:BaseUrl"] = OperationsOrigin.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:operations:Authorization:RequiredClaims:0:Claim"] = OperationsClaim,
            [$"{C.AuthProxy.SectionKey}:Services:operations:Authorization:RequiredClaims:0:AnyOf:0"] = OperationsClaimValue,

            [$"{C.AuthProxy.SectionKey}:Services:chronicle:Hosts:0"] = ChronicleHost,
            [$"{C.AuthProxy.SectionKey}:Services:chronicle:ResolveIdentityDetails"] = "false",
            [$"{C.AuthProxy.SectionKey}:Services:chronicle:Backend:BaseUrl"] = ChronicleOrigin.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:chronicle:Frontend:BaseUrl"] = ChronicleOrigin.BaseUrl,

            [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

            // A trusted destination for a sign-out that lies outside the cookie domain, so a spec can show that a
            // sign-in is still refused there.
            [$"{C.AuthProxy.SectionKey}:Logout:AllowedRedirectOrigins:0"] = OutsideTheDomainOrigin,

            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,
        };

        if (CookieDomain is not null)
        {
            settings[$"{C.Session.SectionKey}:{nameof(C.Session.CookieDomain)}"] = CookieDomain;
        }

        if (CallbackHost is not null)
        {
            settings[$"{C.AuthProxy.SectionKey}:SignIn:{nameof(C.SignIn.CallbackHost)}"] = CallbackHost;
        }

        // Providers are registered while the application is built, ahead of the deferred configuration callbacks,
        // so the provider is supplied as a setting. It is an OAuth provider because its challenge needs no discovery
        // document; the token and user endpoints are answered by FakeIdentityProvider below.
        builder
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:Name", ProviderName)
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint", ProviderAuthorizationEndpoint)
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint", "http://idp.test/token")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint", "http://idp.test/user")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId", "test-client")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret", "test-secret")
            .UseSetting($"{C.Authentication.SectionKey}:OAuthProviders:0:ClaimMappings:sub", "id");

        builder
            .UseEnvironment("Production")
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(settings))
            .ConfigureTestServices(services =>
            {
                services.AddTransient<IStartupFilter, SignInStartupFilter>();
                services.PostConfigure<OAuthOptions>(
                    ProviderScheme,
                    options => options.Backchannel = new HttpClient(new FakeIdentityProvider()) { Timeout = TimeSpan.FromSeconds(10) });
            });
    }

    /// <summary>
    /// Adds the one endpoint that stands in for a completed identity-provider handshake.
    /// </summary>
    sealed class SignInStartupFilter : IStartupFilter
    {
        /// <inheritdoc/>
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
            app =>
            {
                app.Use(async (context, proceed) =>
                {
                    if (!context.Request.Path.Equals(SignInPath, StringComparison.Ordinal))
                    {
                        await proceed();
                        return;
                    }

                    var user = Guid.NewGuid().ToString("N");
                    var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, user), new("oid", user), new(ClaimTypes.Name, user) };
                    if (string.Equals(context.Request.Query[OperationsQueryKey], bool.TrueString, StringComparison.OrdinalIgnoreCase))
                    {
                        claims.Add(new Claim(OperationsClaim, OperationsClaimValue));
                    }

                    await context.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
                    context.Response.StatusCode = StatusCodes.Status204NoContent;
                });

                next(app);
            };
    }

    /// <summary>
    /// Answers the identity provider's token and user-information endpoints.
    /// </summary>
    sealed class FakeIdentityProvider : HttpMessageHandler
    {
        /// <inheritdoc/>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri?.ToString() ?? string.Empty;
            var body = url switch
            {
                _ when url.StartsWith("http://idp.test/token", StringComparison.OrdinalIgnoreCase) => /*lang=json,strict*/ "{\"access_token\":\"test-access-token\",\"token_type\":\"Bearer\"}",
                _ when url.StartsWith("http://idp.test/user", StringComparison.OrdinalIgnoreCase) => /*lang=json,strict*/ "{\"id\":\"provider-user-1\"}",
                _ => null
            };

            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") });
        }
    }
}
