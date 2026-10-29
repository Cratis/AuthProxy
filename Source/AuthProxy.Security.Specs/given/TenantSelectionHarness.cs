// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy that resolves the tenant from a selection, in front of one service with a declared anonymous
/// path and registration enabled, with recording origins for the service and a tenants endpoint the spec controls.
/// </summary>
/// <remarks>
/// The session is stood in for by <see cref="SecurityHarness.AuthenticatedUserHeader"/>. What is under test is the
/// request path: that a selected tenant is forwarded only once it has been confirmed for the signed-in account.
/// </remarks>
public class TenantSelectionHarness : WebApplicationFactory<Program>
{
    /// <summary>The path of the declared anonymous path.</summary>
    public const string AnonymousPath = "/public";

    /// <summary>The first tenant.</summary>
    public const string TenantA = "tenant-a";

    /// <summary>The second tenant.</summary>
    public const string TenantB = "tenant-b";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="TenantSelectionHarness"/> class.
    /// </summary>
    public TenantSelectionHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        foreach (var page in new[] { WellKnownPageNames.SelectProvider, WellKnownPageNames.SelectTenant, WellKnownPageNames.ServiceUnavailable })
        {
            File.WriteAllText(Path.Combine(_pagesPath, page), $"<html><body>{page}</body></html>");
        }

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>Gets the origin of the service and of the tenants endpoint.</summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Makes the tenants endpoint list the given tenants.
    /// </summary>
    /// <param name="tenants">The tenants the signed-in user belongs to.</param>
    public void UserBelongsTo(params string[] tenants) =>
        Origin.TenantsResponse = () => Results.Json(tenants.Select(tenant => new { id = tenant, name = tenant }));

    /// <summary>
    /// Makes the tenants endpoint fail.
    /// </summary>
    public void TenantsEndpointFails() =>
        Origin.TenantsResponse = () => Results.StatusCode(StatusCodes.Status500InternalServerError);

    /// <summary>
    /// Gets the requests the service received that carried a tenant header naming a tenant.
    /// </summary>
    /// <param name="tenant">The tenant.</param>
    /// <returns>The requests.</returns>
    public IReadOnlyList<ForwardedRequest> RequestsForTenant(string tenant) =>
        [.. Origin.Received.Where(request => string.Equals(request.Value(Headers.TenantId), tenant, StringComparison.Ordinal))];

    /// <summary>
    /// Creates a client that surfaces redirects as responses rather than following them.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateSecurityClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <summary>
    /// Selects a tenant as the given user and returns the selected-tenant cookie the proxy issued.
    /// </summary>
    /// <param name="client">The client.</param>
    /// <param name="user">The signed-in user.</param>
    /// <param name="tenant">The tenant to select.</param>
    /// <returns>The cookie as <c language="text">name=value</c>.</returns>
    public async Task<string> SelectTenant(HttpClient client, string user, string tenant)
    {
        var response = await client.SendAsync(SecurityHarness.Authenticated(HttpMethod.Get, $"{WellKnownPaths.SelectTenant}?tenantId={tenant}", user));
        var header = response.Headers.GetValues("Set-Cookie").First(value => value.StartsWith($"{Cookies.Tenant}=", StringComparison.Ordinal));
        return header[..header.IndexOf(';', StringComparison.Ordinal)];
    }

    /// <summary>
    /// Builds a request from a signed-in user that carries cookies.
    /// </summary>
    /// <param name="pathAndQuery">The path and query.</param>
    /// <param name="user">The signed-in user.</param>
    /// <param name="cookies">The cookies to send.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage Request(string pathAndQuery, string user, params string[] cookies)
    {
        var request = SecurityHarness.Authenticated(HttpMethod.Get, pathAndQuery, user);
        if (cookies.Length > 0)
        {
            request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies));
        }

        return request;
    }

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
                [$"{C.AuthProxy.SectionKey}:Services:app:ResolveIdentityDetails"] = "false",
                [$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
                [$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:0"] = AnonymousPath,

                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Selection),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantsEndpoint"] = Origin.TenantsUrl,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
            }))
            .ConfigureTestServices(services => services
                .AddAuthentication(HeaderAuthenticationHandler.Scheme)
                .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, HeaderAuthenticationHandler>(
                    HeaderAuthenticationHandler.Scheme,
                    _ => { }));
    }
}
