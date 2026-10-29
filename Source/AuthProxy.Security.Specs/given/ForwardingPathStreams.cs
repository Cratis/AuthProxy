// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.WebSockets;
using System.Text;

namespace Cratis.AuthProxy.Security.given;

/// <summary>Exchanges stream payloads when the public path differs from the recorded origin path.</summary>
/// <param name="harness">The proxy and recording origins.</param>
public class ForwardingPathStreams(ForwardingPathHarness harness)
{
    /// <summary>Checks an upgraded connection through the reports prefix.</summary>
    /// <param name="client">The proxy client.</param>
    /// <returns>The asynchronous exchange.</returns>
    public async Task WebSocket(HttpClient client)
    {
        harness.ClearOrigins();
        using var request = ServiceRoutingHarness.Request("/reports/api/routing-websocket");
        using var socket = new ClientWebSocket();
        foreach (var header in request.Headers)
        {
            socket.Options.SetRequestHeader(header.Key, string.Join(',', header.Value));
        }
        using var deadline = Deadline();
        var uri = new UriBuilder(new Uri(client.BaseAddress, request.RequestUri)) { Scheme = "ws" }.Uri;
        await socket.ConnectAsync(uri, deadline.Token);
        await AssertPayload(socket, deadline.Token);
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", deadline.Token);
        harness.AssertOnlyOrigin(harness.Reports, "/api/routing-websocket");
    }

    /// <summary>Checks an event stream through the reports prefix.</summary>
    /// <param name="client">The proxy client.</param>
    /// <returns>The asynchronous exchange.</returns>
    public async Task ServerSentEvents(HttpClient client)
    {
        harness.ClearOrigins();
        using var request = ServiceRoutingHarness.Request("/reports/api/routing-events");
        request.Headers.Accept.ParseAdd("text/event-stream");
        using var deadline = Deadline();
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType?.MediaType);
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(deadline.Token));
        Assert.Equal("data: origin", await reader.ReadLineAsync(deadline.Token));
        Assert.Equal(string.Empty, await reader.ReadLineAsync(deadline.Token));
        harness.AssertOnlyOrigin(harness.Reports, "/api/routing-events");
    }

    static async Task AssertPayload(ClientWebSocket socket, CancellationToken token)
    {
        var buffer = new byte[32];
        var received = await socket.ReceiveAsync(buffer.AsMemory(), token);
        Assert.Equal(WebSocketMessageType.Text, received.MessageType);
        Assert.True(received.EndOfMessage);
        Assert.Equal("origin", Encoding.UTF8.GetString(buffer, 0, received.Count));
    }

    static CancellationTokenSource Deadline()
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        return deadline;
    }
}
