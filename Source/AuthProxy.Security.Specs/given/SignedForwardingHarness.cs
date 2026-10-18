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
/// A running AuthProxy that signs what it forwards, in front of two services with their own recording origins.
/// </summary>
/// <remarks>
/// The reports service is reached under a stripped path prefix, states its own forwarding audience and resolves
/// identity details, so one request shows the signed path is the rewritten one and the back-channel is signed too.
/// The app service is reached by host and states no audience, so its assertions carry its configuration key.
/// </remarks>
public class SignedForwardingHarness : WebApplicationFactory<Program>
{
    /// <summary>The path prefix of the reports service, which strips it.</summary>
    public const string ReportsPrefix = "/reports";

    /// <summary>The forwarding audience the reports service states.</summary>
    public const string ReportsAudience = "reports-api";

    /// <summary>The anonymous path of the reports service, as the caller requests it.</summary>
    public const string AnonymousPath = $"{ReportsPrefix}/public";

    /// <summary>The host of the app service.</summary>
    public const string AppHost = "app.example.test";

    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "44444444-4444-4444-4444-444444444444";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="SignedForwardingHarness"/> class.
    /// </summary>
    public SignedForwardingHarness()
    {
        // A host-selected service needs a real Host header, which only a real listener sees.
        UseKestrel(0);
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "forbidden.html"), "<html><body>Forbidden</body></html>");

        Key = SignedForwarding.Generate();
        Reports = RecordingBackend.Start().GetAwaiter().GetResult();
        App = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>Gets the signing key, whose public half a backend would pin.</summary>
    public SignedForwarding Key { get; }

    /// <summary>Gets the origin of the reports service.</summary>
    public RecordingBackend Reports { get; }

    /// <summary>Gets the origin of the app service.</summary>
    public RecordingBackend App { get; }

    /// <summary>
    /// Forgets what every origin received.
    /// </summary>
    public void ClearOrigins()
    {
        Reports.Clear();
        App.Clear();
    }

    /// <summary>
    /// Creates a client that surfaces redirects as responses and sends only the cookies a spec puts on a request.
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
        App.DisposeAsync().AsTask().GetAwaiter().GetResult();

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
            [$"{C.AuthProxy.SectionKey}:Services:reports:PathPrefix"] = ReportsPrefix,
            [$"{C.AuthProxy.SectionKey}:Services:reports:StripPathPrefix"] = "true",
            [$"{C.AuthProxy.SectionKey}:Services:reports:ForwardingAudience"] = ReportsAudience,
            [$"{C.AuthProxy.SectionKey}:Services:reports:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
            [$"{C.AuthProxy.SectionKey}:Services:reports:Backend:BaseUrl"] = Reports.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:reports:Frontend:BaseUrl"] = Reports.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:reports:AnonymousPaths:0"] = AnonymousPath,

            [$"{C.AuthProxy.SectionKey}:Services:app:Hosts:0"] = AppHost,
            [$"{C.AuthProxy.SectionKey}:Services:app:ResolveIdentityDetails"] = "false",
            [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = App.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = App.BaseUrl,

            [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
        };
        Key.AddTo(settings);

        builder
            .UseEnvironment("Production")
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(settings))
            .ConfigureTestServices(services => services
                .AddAuthentication(HeaderAuthenticationHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(
                    HeaderAuthenticationHandler.Scheme,
                    _ => { }));
    }
}
