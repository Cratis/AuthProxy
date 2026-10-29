// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A real proxy with allow-listed reports, deny-listed portal and unrestricted admin services.</summary>
public class ForwardingPathHarness : ServiceRoutingHarness
{
    /// <summary>The host of the deny-listed portal service.</summary>
    public const string PortalHost = "portal.example.test";

    /// <summary>Sends a request target verbatim so Kestrel, rather than Uri, normalizes it.</summary>
    /// <param name="method">The HTTP method.</param>
    /// <param name="requestTarget">The raw request target.</param>
    /// <param name="host">The service-selection host.</param>
    /// <param name="authenticated">Whether to present a unique browser-session identity.</param>
    /// <param name="headers">Additional headers.</param>
    /// <returns>The status code returned by the proxy.</returns>
    public async Task<HttpStatusCode> Raw(string method, string requestTarget, string host, bool authenticated, params (string Name, string Value)[] headers)
    {
        using var http = CreateSecurityClient();
        using var deadline = Deadline();
        using var client = new TcpClient();
        await client.ConnectAsync(http.BaseAddress!.Host, http.BaseAddress.Port, deadline.Token);
        await using var stream = client.GetStream();
        var request = new StringBuilder($"{method} {requestTarget} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        if (authenticated)
        {
            request.Append($"{SecurityHarness.AuthenticatedUserHeader}: {SecurityHarness.UniqueUser("forwarding-paths")}\r\n");
        }
        foreach (var (name, value) in headers)
        {
            request.Append($"{name}: {value}\r\n");
        }
        request.Append("\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request.ToString()), deadline.Token);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var statusLine = await reader.ReadLineAsync(deadline.Token);
        Assert.NotNull(statusLine);
        return (HttpStatusCode)int.Parse(statusLine.Split(' ')[1], CultureInfo.InvariantCulture);
    }

    /// <summary>Asserts that not one request reached any origin.</summary>
    public void AssertNoOrigins()
    {
        foreach (var origin in Origins())
        {
            Assert.Empty(origin.Received);
        }
    }

    /// <summary>Asserts the exact forwarded path and that no other origin was contacted.</summary>
    /// <param name="target">The expected origin.</param>
    /// <param name="path">The path relative to the origin.</param>
    public void AssertOnlyOrigin(RecordingBackend target, string path)
    {
        Assert.Equal(path, Assert.Single(target.Received).Path);
        foreach (var other in Origins().Where(origin => origin != target))
        {
            Assert.Empty(other.Received);
        }
    }

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string reports = $"{C.AuthProxy.SectionKey}:Services:reports";
        const string portal = $"{C.AuthProxy.SectionKey}:Services:portal";
        AddPaths(settings, $"{reports}:ForwardedPaths", ["/api/allowed", "/api/routing-websocket", "/api/routing-events", "/api/health", "/"]);
        settings[$"{reports}:ForwardedPaths:1:Methods:0"] = "GET";
        settings[$"{reports}:ForwardedPaths:2:Methods:0"] = "GET";
        settings[$"{reports}:ForwardedPaths:4:Match"] = "Exact";
        AddPaths(settings, $"{reports}:DeniedPaths", ["/api/allowed/secret"]);
        settings[$"{reports}:AnonymousPaths:1"] = "/reports/api/hook";
        AddPaths(settings, $"{portal}:DeniedPaths", ["/.cratis/commands", "/.cratis/queries", "/openapi", "/api/report", "/api/items"]);
        settings[$"{portal}:DeniedPaths:3:Methods:0"] = "GET";
        settings[$"{portal}:DeniedPaths:4:Methods:0"] = "DELETE";
    }

    static void AddPaths(IDictionary<string, string?> settings, string key, string[] paths)
    {
        for (var index = 0; index < paths.Length; index++)
        {
            settings[$"{key}:{index.ToString(CultureInfo.InvariantCulture)}:Path"] = paths[index];
        }
    }

    static CancellationTokenSource Deadline()
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        return deadline;
    }

    RecordingBackend[] Origins() => [Reports, ReportsFrontend, Admin, Portal];
}
