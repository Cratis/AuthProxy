// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.WebSockets;
using System.Text;

namespace Cratis.AuthProxy.Security.for_ServiceRouting;

/// <summary>
/// WebSocket upgrades and SSE reach the same origins and receive the same path transforms as ordinary requests.
/// </summary>
/// <param name="harness">The running proxy and its origins.</param>
[Collection(ServiceRoutingSpecCollection.Name)]
public class when_streaming_protocols_use_service_routes(ServiceRoutingHarness harness)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_forward_a_websocket_upgrade(bool byHost)
    {
        harness.ClearOrigins();
        var path = $"{(byHost ? string.Empty : ServiceRoutingHarness.ReportsPrefix)}/api/routing-websocket";
        var host = byHost ? ServiceRoutingHarness.AdminHost : "localhost";
        using var request = ServiceRoutingHarness.Request(path, host, withAdminClaim: byHost);
        using var client = harness.CreateSecurityClient();
        using var socket = new ClientWebSocket();
        foreach (var header in request.Headers)
        {
            socket.Options.SetRequestHeader(header.Key, string.Join(',', header.Value));
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var uri = new UriBuilder(new Uri(client.BaseAddress!, path)) { Scheme = "ws" }.Uri;
        await socket.ConnectAsync(uri, timeout.Token);
        var buffer = new byte[32];
        var received = await socket.ReceiveAsync(buffer.AsMemory(), timeout.Token);

        Assert.Equal(WebSocketMessageType.Text, received.MessageType);
        Assert.Equal("origin", Encoding.UTF8.GetString(buffer, 0, received.Count));
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", timeout.Token);
        AssertForwarded(byHost, "/api/routing-websocket");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_forward_server_sent_events(bool byHost)
    {
        harness.ClearOrigins();
        using var client = harness.CreateSecurityClient();
        var path = $"{(byHost ? string.Empty : ServiceRoutingHarness.ReportsPrefix)}/api/routing-events";
        using var request = ServiceRoutingHarness.Request(path, byHost ? ServiceRoutingHarness.AdminHost : null, withAdminClaim: byHost);
        request.Headers.Accept.ParseAdd("text/event-stream");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType!.MediaType);
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(timeout.Token));
        Assert.Equal("data: origin", await reader.ReadLineAsync(timeout.Token));
        Assert.Equal(string.Empty, await reader.ReadLineAsync(timeout.Token));
        AssertForwarded(byHost, "/api/routing-events");
    }

    void AssertForwarded(bool byHost, string path)
    {
        var target = byHost ? harness.Admin : harness.Reports;
        var other = byHost ? harness.Reports : harness.Admin;
        var forwarded = target.LastRequestTo(path);
        Assert.NotNull(forwarded);
        if (!byHost)
        {
            Assert.Equal(ServiceRoutingHarness.ReportsPrefix, forwarded.Value("X-Forwarded-Prefix"));
        }

        Assert.False(other.ReceivedAnythingFor(path));
        Assert.False(harness.Portal.ReceivedAnythingFor(path));
        Assert.False(harness.ReportsFrontend.ReceivedAnythingFor(path));
    }
}
