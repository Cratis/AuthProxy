// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.WebSockets;
using System.Text;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Exchanges real observable payloads with bounded connections and checks which recording origin received them.
/// </summary>
/// <param name="harness">The real proxy and recording origins.</param>
public class ObservableConnections(ServiceRoutingHarness harness)
{
    internal async Task WebSocket(HttpClient client, HttpRequestMessage request, string service)
    {
        harness.ClearOrigins();
        request.RequestUri = new Uri(client.BaseAddress, request.RequestUri);
        using var socket = CreateSocket(request);
        using var timeout = Deadline();
        var uri = new UriBuilder(request.RequestUri) { Scheme = "ws" }.Uri;
        await socket.ConnectAsync(uri, timeout.Token);
        var buffer = new byte[32];
        var received = await socket.ReceiveAsync(buffer.AsMemory(), timeout.Token);
        Assert.Equal(WebSocketMessageType.Text, received.MessageType);
        Assert.True(received.EndOfMessage);
        Assert.Equal("origin", Encoding.UTF8.GetString(buffer, 0, received.Count));
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", timeout.Token);
        AssertDestination(service, request);
    }

    internal async Task ServerSentEvents(HttpClient client, HttpRequestMessage request, string service)
    {
        harness.ClearOrigins();
        request.Headers.Accept.ParseAdd("text/event-stream");
        using var timeout = Deadline();
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/event-stream", response.Content.Headers.ContentType.MediaType);
        using var reader = new StreamReader(await response.Content.ReadAsStreamAsync(timeout.Token));
        Assert.Equal("data: origin", await reader.ReadLineAsync(timeout.Token));
        Assert.Equal(string.Empty, await reader.ReadLineAsync(timeout.Token));
        AssertDestination(service, request);
    }

    internal async Task DeniedWebSocket(HttpClient client, HttpRequestMessage request)
    {
        harness.ClearOrigins();
        request.RequestUri = new Uri(client.BaseAddress, request.RequestUri);
        using var socket = CreateSocket(request);
        socket.Options.CollectHttpResponseDetails = true;
        using var timeout = Deadline();
        var uri = new UriBuilder(request.RequestUri) { Scheme = "ws" }.Uri;
        await Assert.ThrowsAsync<WebSocketException>(() => socket.ConnectAsync(uri, timeout.Token));
        Assert.Equal(HttpStatusCode.Forbidden, socket.HttpStatusCode);
        AssertNoOrigin(request);
    }

    internal async Task DeniedServerSentEvents(HttpClient client, HttpRequestMessage request)
    {
        harness.ClearOrigins();
        request.Headers.Accept.ParseAdd("text/event-stream");
        using var timeout = Deadline();
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        AssertNoOrigin(request);
    }

    void AssertDestination(string service, HttpRequestMessage request)
    {
        var target = service switch { "reports" => harness.Reports, "admin" => harness.Admin, _ => harness.Portal };
        var forwarded = Assert.IsType<ForwardedRequest>(target.LastRequestTo(request.RequestUri.AbsolutePath));
        Assert.Equal(request.RequestUri.Query, forwarded.QueryString);
        Assert.Equal(service, forwarded.Value(Headers.ServiceId));
        Assert.Equal(service, forwarded.Value(Headers.LegacyServiceId));
        foreach (var other in new[] { harness.Reports, harness.Admin, harness.Portal, harness.ReportsFrontend }.Where(_ => _ != target))
        {
            Assert.False(other.ReceivedAnythingFor(request.RequestUri.AbsolutePath));
        }
    }

    void AssertNoOrigin(HttpRequestMessage request)
    {
        foreach (var origin in new[] { harness.Reports, harness.Admin, harness.Portal, harness.ReportsFrontend })
        {
            Assert.False(origin.ReceivedAnythingFor(request.RequestUri.AbsolutePath));
        }
    }

    static ClientWebSocket CreateSocket(HttpRequestMessage request)
    {
        var socket = new ClientWebSocket();
        foreach (var header in request.Headers)
        {
            socket.Options.SetRequestHeader(header.Key, string.Join(',', header.Value));
        }
        return socket;
    }

    static CancellationTokenSource Deadline()
    {
        var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        return timeout;
    }
}
