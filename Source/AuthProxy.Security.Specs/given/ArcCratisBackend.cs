// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A loopback Arc origin with a coordinated event stream and a WebSocket echo endpoint.</summary>
public sealed class ArcCratisBackend : IAsyncDisposable
{
    readonly WebApplication _app;

    ArcCratisBackend(WebApplication app) => _app = app;

    public string BaseUrl => _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>().Addresses.Single();

    public ConcurrentQueue<ForwardedRequest> Received { get; } = new();

    public TaskCompletionSource FirstEventRead { get; private set; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource<string> SocketMessage { get; private set; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Forgets recorded requests and the one-shot coordination of earlier specs sharing this origin.</summary>
    public void Reset()
    {
        Received.Clear();
        FirstEventRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        SocketMessage = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    public static async Task<ArcCratisBackend> Start()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var backend = new ArcCratisBackend(app);
        app.UseWebSockets();
        app.Use(async (context, next) =>
        {
            backend.Received.Enqueue(new(
                context.Request.Method,
                context.Request.Path.Value ?? string.Empty,
                context.Request.QueryString.Value ?? string.Empty,
                context.Request.Headers.ToDictionary(header => header.Key, header => header.Value.ToString(), StringComparer.OrdinalIgnoreCase)));
            await next();
        });
        app.MapGet("/.cratis/queries/books", () => Results.Text("arc-query-result", "text/plain", statusCode: StatusCodes.Status202Accepted));
        app.MapPost("/.cratis/commands/publish", () => Results.Text("arc-command-result", "text/plain", statusCode: StatusCodes.Status201Created));
        app.MapGet("/.cratis/queries/sse", backend.StreamEvents);
        app.MapGet("/.cratis/ws", backend.Echo);

        // The remaining Arc-owned discovery, health and multiplexed-query endpoints (Arc.Core).
        app.MapPost("/.cratis/queries/sse/subscribe", async context => await Results.Text("subscribe:" + await new StreamReader(context.Request.Body).ReadToEndAsync(), "text/plain", statusCode: StatusCodes.Status202Accepted).ExecuteAsync(context));
        app.MapPost("/.cratis/queries/sse/unsubscribe", async context => await Results.Text("unsubscribe:" + await new StreamReader(context.Request.Body).ReadToEndAsync(), "text/plain", statusCode: StatusCodes.Status202Accepted).ExecuteAsync(context));
        app.MapGet("/.cratis/queries/ws", backend.Echo);
        app.MapGet("/.cratis/queries/health", () => Results.Text("arc-query-health", "text/plain", statusCode: StatusCodes.Status200OK));
        app.MapGet("/.cratis/users", () => Results.Text("arc-users", "text/plain", statusCode: StatusCodes.Status200OK));
        app.MapGet("/.cratis/tenants", () => Results.Text("arc-tenants", "text/plain", statusCode: StatusCodes.Status200OK));
        app.MapGet("/.cratis/identity-details/schema", () => Results.Text("arc-identity-schema", "text/plain", statusCode: StatusCodes.Status200OK));

        // A forwarded proxy-owned request must be distinguishable from AuthProxy's own response.
        app.MapFallback(() => Results.Text("unexpected-origin-request", statusCode: StatusCodes.Status418ImATeapot));
        await app.StartAsync();
        return backend;
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    async Task StreamEvents(HttpContext context)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        context.Response.ContentType = "text/event-stream";
        await context.Response.WriteAsync("data: first\n\n", deadline.Token);
        await context.Response.Body.FlushAsync(deadline.Token);
        await FirstEventRead.Task.WaitAsync(deadline.Token);
        await context.Response.WriteAsync("data: second\n\n", deadline.Token);
        await context.Response.Body.FlushAsync(deadline.Token);
    }

    async Task Echo(HttpContext context)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var socket = await context.WebSockets.AcceptWebSocketAsync();
        var buffer = new byte[128];
        var message = await socket.ReceiveAsync(buffer.AsMemory(), deadline.Token);
        SocketMessage.TrySetResult(Encoding.UTF8.GetString(buffer, 0, message.Count));
        await socket.SendAsync(buffer.AsMemory(0, message.Count), message.MessageType, message.EndOfMessage, deadline.Token);
        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", deadline.Token);
    }
}
