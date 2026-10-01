// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy in front of three services told apart by path prefix, by host, and by name only, each with
/// its own recording origin.
/// </summary>
/// <remarks>
/// End to end because the route table and the authorization gate are separate components that have to agree on
/// which service a request targets. Only a running proxy shows that the service whose requirements were checked
/// is the service that received the request.
/// </remarks>
public class ServiceRoutingHarness : WebApplicationFactory<Program>
{
    /// <summary>The path prefix of the reports service, which strips it.</summary>
    public const string ReportsPrefix = "/reports";

    /// <summary>The host of the admin service, which requires <see cref="AdminClaim"/>.</summary>
    public const string AdminHost = "admin.example.test";

    /// <summary>The claim the admin service requires.</summary>
    public const string AdminClaim = "urn:github:team";

    /// <summary>The value of <see cref="AdminClaim"/> the admin service accepts.</summary>
    public const string AdminClaimValue = "Cratis/operations";

    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "33333333-3333-3333-3333-333333333333";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="ServiceRoutingHarness"/> class.
    /// </summary>
    public ServiceRoutingHarness()
    {
        // Protocol specs need a real HTTP upgrade feature, not TestServer's in-memory WebSocket feature.
        UseKestrel(0);
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");

        Reports = RecordingBackend.Start().GetAwaiter().GetResult();
        Admin = RecordingBackend.Start().GetAwaiter().GetResult();
        Portal = RecordingBackend.Start().GetAwaiter().GetResult();
        ReportsFrontend = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>Gets the origin of the service reached by <see cref="ReportsPrefix"/>.</summary>
    public RecordingBackend Reports { get; }

    /// <summary>Gets the origin of the service reached by <see cref="AdminHost"/>.</summary>
    public RecordingBackend Admin { get; }

    /// <summary>Gets the frontend origin of the reports service.</summary>
    public RecordingBackend ReportsFrontend { get; }

    /// <summary>Gets the origin of the portal service.</summary>
    public RecordingBackend Portal { get; }

    /// <summary>
    /// Builds a request from an authenticated caller, optionally for a host and carrying the admin claim.
    /// </summary>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <param name="host">The host to request, or <see langword="null"/> for the default.</param>
    /// <param name="withAdminClaim">Whether the caller carries the claim the admin service requires.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage Request(string pathAndQuery, string? host = null, bool withAdminClaim = false)
    {
        var request = SecurityHarness.Authenticated(HttpMethod.Get, pathAndQuery, SecurityHarness.UniqueUser("routing"));
        if (host is not null)
        {
            request.Headers.Host = host;
        }

        if (withAdminClaim)
        {
            request.Headers.TryAddWithoutValidation(HeaderAuthenticationHandler.ClaimsHeader, $"{AdminClaim}={AdminClaimValue}");
        }

        return request;
    }

    /// <summary>
    /// Forgets what every origin received.
    /// </summary>
    public void ClearOrigins()
    {
        Reports.Clear();
        ReportsFrontend.Clear();
        Admin.Clear();
        Portal.Clear();
    }

    /// <summary>
    /// Creates a client that surfaces redirects as responses rather than following them.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateSecurityClient()
    {
        StartServer();
        var address = Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();

        return CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(address),
            AllowAutoRedirect = false,
            HandleCookies = false,
        });
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        Reports.DisposeAsync().AsTask().GetAwaiter().GetResult();
        ReportsFrontend.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Admin.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Portal.DisposeAsync().AsTask().GetAwaiter().GetResult();

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
                [$"{C.AuthProxy.SectionKey}:Services:reports:PathPrefix"] = ReportsPrefix,
                [$"{C.AuthProxy.SectionKey}:Services:reports:StripPathPrefix"] = "true",
                [$"{C.AuthProxy.SectionKey}:Services:reports:Backend:BaseUrl"] = Reports.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:reports:Frontend:BaseUrl"] = ReportsFrontend.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:reports:AnonymousPaths:0"] = $"{ReportsPrefix}/api/health",

                [$"{C.AuthProxy.SectionKey}:Services:admin:Hosts:0"] = AdminHost,
                [$"{C.AuthProxy.SectionKey}:Services:admin:Backend:BaseUrl"] = Admin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:admin:Frontend:BaseUrl"] = Admin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:admin:Authorization:RequiredClaims:0:Claim"] = AdminClaim,
                [$"{C.AuthProxy.SectionKey}:Services:admin:Authorization:RequiredClaims:0:AnyOf:0"] = AdminClaimValue,

                [$"{C.AuthProxy.SectionKey}:Services:portal:Hosts:0"] = "portal.example.test",
                [$"{C.AuthProxy.SectionKey}:Services:portal:Hosts:1"] = "xn--bcher-kva.example.test",
                [$"{C.AuthProxy.SectionKey}:Services:portal:Backend:BaseUrl"] = Portal.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:portal:Frontend:BaseUrl"] = Portal.BaseUrl,

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
