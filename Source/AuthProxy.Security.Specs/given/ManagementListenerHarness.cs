// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Net.Sockets;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.Links;
using Cratis.AuthProxy.Management;
using Cratis.AuthProxy.ReverseProxy;
using Cratis.AuthProxy.SignIns;
using Cratis.AuthProxy.Tenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Two AuthProxy deployments on real Kestrel sockets — one that opened a management listener and one that
/// did not — in front of one real recording origin.
/// </summary>
/// <remarks>
/// Real sockets, deliberately, and the only place in this suite that needs them. Every other security spec
/// runs on <c>WebApplicationFactory</c>'s in-memory test server, which has no socket at all and reports
/// <c>Connection.LocalPort</c> as zero — so every assertion about which listener a request arrived on would
/// pass without proving anything, including against an implementation that isolated nothing.
/// <para>
/// The bare deployment is here because "no management section changes nothing" is a claim about what is
/// <em>not</em> bound, and the only way to see that is to enumerate the addresses of a process configured
/// exactly like the other one minus the section.
/// </para>
/// <para>
/// The pipeline mirrors <c>Program.cs</c> rather than running it, because these specs have to choose the
/// addresses and the origin before the host is built. The registration and the pipeline placement it
/// mirrors are the two things under test, so both are called here exactly as the program calls them.
/// </para>
/// </remarks>
public sealed class ManagementListenerHarness : IDisposable
{
    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "33333333-3333-3333-3333-333333333333";

    /// <summary>The one ordinary path this deployment declares anonymous, and proxies to the origin.</summary>
    public const string AnonymousPath = "/public";

    /// <summary>
    /// A path the application itself serves, under the very prefix the management paths live under, and
    /// declares anonymous. Nothing about opening a management listener may take it away from the backend.
    /// </summary>
    public const string ApplicationHealthPath = "/health";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly string _keysPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly WebApplication _configured;
    readonly WebApplication _bare;

    /// <summary>
    /// Initializes a new instance of the <see cref="ManagementListenerHarness"/> class.
    /// </summary>
    /// <remarks>
    /// The origin has to exist before either proxy is configured, because its address is what they are
    /// configured to forward to, and both have to be listening before a spec asks what they bound. A
    /// fixture constructor cannot be async, so the starts are awaited here.
    /// </remarks>
    public ManagementListenerHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        Directory.CreateDirectory(_keysPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
        ManagementPort = FreePort();

        _configured = Build(Origin, _pagesPath, _keysPath, ManagementPort);
        _bare = Build(Origin, _pagesPath, _keysPath, null);

        _configured.StartAsync().GetAwaiter().GetResult();
        _bare.StartAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the origin AuthProxy forwards to, and the record of what reached it.
    /// </summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Gets the port the management listener was told to bind.
    /// </summary>
    public int ManagementPort { get; }

    /// <summary>
    /// Gets the addresses the deployment that opened a management listener actually bound.
    /// </summary>
    public IReadOnlyList<string> ConfiguredAddresses => AddressesOf(_configured);

    /// <summary>
    /// Gets the addresses the deployment that never asked for one actually bound.
    /// </summary>
    public IReadOnlyList<string> BareAddresses => AddressesOf(_bare);

    /// <summary>
    /// Gets the base URL of the public listener of the deployment that opened a management listener.
    /// </summary>
    public string PublicBaseUrl =>
        ConfiguredAddresses.Single(address => ListenerAddresses.PortOf(address) != ManagementPort).TrimEnd('/');

    /// <summary>
    /// Gets the base URL of the management listener.
    /// </summary>
    public string ManagementBaseUrl => $"http://127.0.0.1:{ManagementPort.ToString(CultureInfo.InvariantCulture)}";

    /// <summary>
    /// Gets how many times anything inside AuthProxy asked for an outbound HTTP client.
    /// </summary>
    public int OutboundClientsCreated => _configured.Services.GetRequiredService<CountingHttpClientFactory>().Created;

    /// <summary>
    /// Creates a client that surfaces redirects as responses rather than following them.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public static HttpClient CreateClient() =>
        new(new HttpClientHandler { AllowAutoRedirect = false, CheckCertificateRevocationList = true });

    /// <inheritdoc/>
    public void Dispose()
    {
        _configured.StopAsync().GetAwaiter().GetResult();
        _configured.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _bare.StopAsync().GetAwaiter().GetResult();
        _bare.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Origin.DisposeAsync().AsTask().GetAwaiter().GetResult();

        Delete(_pagesPath);
        Delete(_keysPath);
    }

    static IReadOnlyList<string> AddressesOf(WebApplication app) =>
        [.. app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses];

    static int FreePort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        return port;
    }

    static void Delete(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
    }

    static WebApplication Build(RecordingBackend origin, string pagesPath, string keysPath, int? managementPort)
    {
        var settings = new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = origin.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = origin.BaseUrl,
            [$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:0"] = AnonymousPath,
            [$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:1"] = ApplicationHealthPath,

            [$"{C.AuthProxy.SectionKey}:PagesPath"] = pagesPath,
            [$"{C.AuthProxy.SectionKey}:DataProtectionKeysPath"] = keysPath,

            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one"
        };

        if (managementPort.HasValue)
        {
            settings[$"{C.AuthProxy.SectionKey}:Management:Port"] = managementPort.Value.ToString(CultureInfo.InvariantCulture);
        }

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Configuration.AddInMemoryCollection(settings);

        builder.AddIngressConfiguration();
        builder.AddIngressAuthentication();
        builder.AddIngressAuthorization();
        builder.AddTenancy();
        builder.AddIdentityResolution();
        builder.AddInvites();
        builder.AddLinks();
        builder.AddSignIns();
        builder.SetupReverseProxy();
        builder.AddManagement();

        // Registered last so it wins, and only ever asked for by AuthProxy's own outbound calls — YARP
        // forwards through its own invoker. Anything a management answer did that touched a backend, an
        // identity endpoint or an authority would have had to come through here first.
        builder.Services.AddSingleton<CountingHttpClientFactory>();
        builder.Services.AddSingleton<IHttpClientFactory>(services => services.GetRequiredService<CountingHttpClientFactory>());

        var app = builder.Build();

        app.UseManagement();
        app.UseIngress();

        return app;
    }
}
