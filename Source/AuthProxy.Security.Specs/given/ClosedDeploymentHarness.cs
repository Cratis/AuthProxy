// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Net.Sockets;
using System.Text;
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
/// Two closed AuthProxy deployments on real Kestrel sockets — one that also opened a management listener and
/// one that did not — so a refusal can be read as the bytes that actually leave the process.
/// </summary>
/// <remarks>
/// Real sockets, and for a reason the rest of this suite's harnesses cannot cover. <c>TestServer</c> is not a
/// server: it writes no <c>Server</c> header, honors no <c>AddServerHeader</c>, reports
/// <c>Connection.LocalPort</c> as zero and never serializes a response. Everything a spec observes there is
/// what the *application* wrote, so an exhaustive header comparison taken at that layer proves the
/// application is uniform and says nothing about what a caller receives — which is where both of the
/// distinguishable refusals this harness exists for were hiding.
/// <para>
/// Two deployments, because "opening a health port must not change what the public listener says" is a claim
/// about a difference between two processes, and the only way to see it is to run both.
/// </para>
/// </remarks>
public sealed class ClosedDeploymentHarness : IDisposable
{
    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "44444444-4444-4444-4444-444444444444";

    /// <summary>The one path this deployment declares anonymous — and which admission closes anyway.</summary>
    public const string AnonymousPath = "/public";

    /// <summary>The liveness path the management listener is given.</summary>
    public const string LivePath = "/health/live";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly string _keysPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly WebApplication _withManagement;
    readonly WebApplication _withoutManagement;

    /// <summary>
    /// Initializes a new instance of the <see cref="ClosedDeploymentHarness"/> class.
    /// </summary>
    public ClosedDeploymentHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        Directory.CreateDirectory(_keysPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
        ManagementPort = FreePort();

        _withManagement = Build(Origin, _pagesPath, _keysPath, ManagementPort);
        _withoutManagement = Build(Origin, _pagesPath, _keysPath, null);

        _withManagement.StartAsync().GetAwaiter().GetResult();
        _withoutManagement.StartAsync().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the origin both deployments forward to, and the record of what reached it.
    /// </summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Gets the port the management listener of the configured deployment binds.
    /// </summary>
    public int ManagementPort { get; }

    /// <summary>
    /// Gets the public port of the closed deployment that also opened a management listener.
    /// </summary>
    public int PublicPortWithManagement =>
        PortsOf(_withManagement).Single(port => port != ManagementPort);

    /// <summary>
    /// Gets the public port of the closed deployment that never asked for a management listener.
    /// </summary>
    public int PublicPortWithoutManagement => PortsOf(_withoutManagement).Single();

    /// <summary>
    /// Asks one request over a raw socket and returns every byte that came back.
    /// </summary>
    /// <param name="port">The port to ask.</param>
    /// <param name="path">The path to ask for.</param>
    /// <returns>The response, verbatim, with the <c>Date</c> line removed.</returns>
    /// <remarks>
    /// Raw rather than through <see cref="HttpClient"/> because the question is what the process writes, and
    /// a client hands back a parsed view of it — status line casing, header order, a <c>Server</c> header, a
    /// chunked body framing. <c>Connection: close</c> so the response ends at end of stream and no framing
    /// has to be re-implemented here. Only <c>Date</c> is removed, because it is a clock reading rather than
    /// anything about the request.
    /// </remarks>
    public static async Task<string> Raw(int port, string path)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);

        await using var stream = client.GetStream();
        var request = $"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port.ToString(CultureInfo.InvariantCulture)}\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request));

        using var reader = new StreamReader(stream, Encoding.UTF8);
        var response = await reader.ReadToEndAsync();

        return string.Join(
            "\r\n",
            response.Split("\r\n").Where(line => !line.StartsWith("Date:", StringComparison.OrdinalIgnoreCase)));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _withManagement.StopAsync().GetAwaiter().GetResult();
        _withManagement.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _withoutManagement.StopAsync().GetAwaiter().GetResult();
        _withoutManagement.DisposeAsync().AsTask().GetAwaiter().GetResult();
        Origin.DisposeAsync().AsTask().GetAwaiter().GetResult();

        Delete(_pagesPath);
        Delete(_keysPath);
    }

    static IReadOnlyList<int> PortsOf(WebApplication app) =>
        [.. app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!
            .Addresses.Select(ListenerAddresses.PortOf).Where(port => port.HasValue).Select(port => port!.Value)];

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

            [$"{C.AuthProxy.SectionKey}:PagesPath"] = pagesPath,
            [$"{C.AuthProxy.SectionKey}:DataProtectionKeysPath"] = keysPath,

            [$"{C.Admission.SectionKey}:Mode"] = nameof(C.AdmissionMode.CapabilityOnly),
            [$"{C.Admission.SectionKey}:Capability:VerifierUrl"] = "https://verifier.test/admit",

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

        var app = builder.Build();

        app.UseManagement();
        app.UseIngress();

        return app;
    }
}
