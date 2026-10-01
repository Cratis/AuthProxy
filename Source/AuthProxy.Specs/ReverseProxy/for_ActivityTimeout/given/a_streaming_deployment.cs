// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeout.given;

/// <summary>
/// A real AuthProxy reverse proxy in front of a real streaming origin, both on loopback sockets.
/// </summary>
/// <remarks>
/// Real sockets because the activity timeout is enforced by YARP while it copies bytes between two live
/// connections. An in-memory test server would never exercise that copy loop, so a stream could be asserted
/// as "configured" and still be cut in a deployment.
/// <para>
/// The origin stays quiet for <see cref="Silence"/> between its first and second message. A spec sets the
/// proxy's activity timeout below or above that silence and observes whether the second message arrives.
/// </para>
/// </remarks>
public class a_streaming_deployment : Specification
{
    /// <summary>The time the origin says nothing between its two messages.</summary>
    protected static readonly TimeSpan Silence = TimeSpan.FromSeconds(2);

    /// <summary>The second and final message, which only arrives if the stream was not cut.</summary>
    protected const string FinalMessage = "final";

    WebApplication _origin;
    WebApplication _proxy;

    /// <summary>Gets the proxy's base address.</summary>
    protected string ProxyAddress { get; private set; }

    /// <summary>
    /// Starts the origin and a proxy whose root activity timeout is <paramref name="activityTimeout"/>.
    /// </summary>
    /// <param name="activityTimeout">The idle limit the proxy is configured with.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    protected async Task StartWith(TimeSpan activityTimeout)
    {
        _origin = await StartOrigin();
        var originAddress = AddressOf(_origin);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.Configure<C.AuthProxy>(options =>
        {
            options.ActivityTimeout = activityTimeout;
            options.Services = new Dictionary<string, C.Service>
            {
                ["App"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = originAddress },
                    AnonymousPaths = ["/api/stream"],
                },
            };
        });
        builder.SetupReverseProxy();

        _proxy = builder.Build();
        _proxy.UseReverseProxy();
        await _proxy.StartAsync();
        ProxyAddress = AddressOf(_proxy);
    }

    /// <summary>
    /// Reads a Server-Sent Events stream through the proxy until it ends, however it ends.
    /// </summary>
    /// <returns>Everything received before the stream ended or was cut.</returns>
    protected async Task<string> ReadServerSentEvents()
    {
        var received = new StringBuilder();

        try
        {
            using var client = new HttpClient();
            using var response = await client.GetAsync(
                $"{ProxyAddress}api/stream/sse",
                HttpCompletionOption.ResponseHeadersRead);
            await using var stream = await response.Content.ReadAsStreamAsync();
            using var reader = new StreamReader(stream);

            string? line;
            while ((line = await reader.ReadLineAsync()) is not null)
            {
                received.AppendLine(line);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or WebSocketException)
        {
            // A stream cut by the proxy surfaces as a broken read; what arrived before it is the observation.
        }

        return received.ToString();
    }

    /// <summary>
    /// Reads a WebSocket session through the proxy until it closes, however it closes.
    /// </summary>
    /// <returns>Every text message received before the session ended or was cut.</returns>
    protected async Task<IReadOnlyList<string>> ReadWebSocketMessages()
    {
        var messages = new List<string>();
        using var socket = new ClientWebSocket();

        try
        {
            await socket.ConnectAsync(new Uri($"ws://{new Uri(ProxyAddress).Authority}/api/stream/ws"), CancellationToken.None);

            var buffer = new byte[256];
            while (socket.State == WebSocketState.Open)
            {
                var result = await socket.ReceiveAsync(buffer, CancellationToken.None);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }

                messages.Add(Encoding.UTF8.GetString(buffer, 0, result.Count));
            }
        }
        catch (WebSocketException)
        {
            // A session cut by the proxy surfaces as an aborted socket; what arrived before it is the observation.
        }

        return messages;
    }

    static string AddressOf(WebApplication app) =>
        app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First().TrimEnd('/') + "/";

    static async Task<WebApplication> StartOrigin()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();

        var app = builder.Build();
        app.UseWebSockets();

        app.Map("/api/stream/sse", async context =>
        {
            context.Response.ContentType = "text/event-stream";
            await context.Response.WriteAsync("data: first\n\n");
            await context.Response.Body.FlushAsync();
            await Task.Delay(Silence);
            await context.Response.WriteAsync($"data: {FinalMessage}\n\n");
            await context.Response.Body.FlushAsync();
        });

        app.Map("/api/stream/ws", async context =>
        {
            using var socket = await context.WebSockets.AcceptWebSocketAsync();
            await socket.SendAsync(Encoding.UTF8.GetBytes("first"), WebSocketMessageType.Text, true, CancellationToken.None);
            await Task.Delay(Silence);
            await socket.SendAsync(Encoding.UTF8.GetBytes(FinalMessage), WebSocketMessageType.Text, true, CancellationToken.None);
            await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
        });

        await app.StartAsync();
        return app;
    }

    async Task Destroy()
    {
        if (_proxy is not null)
        {
            await _proxy.DisposeAsync();
        }

        if (_origin is not null)
        {
            await _origin.DisposeAsync();
        }
    }
}
