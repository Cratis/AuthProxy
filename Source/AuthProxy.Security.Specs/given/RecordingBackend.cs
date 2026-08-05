// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A real HTTP origin on loopback that records every request AuthProxy forwards to it.
/// </summary>
/// <remarks>
/// The security question that matters most for a reverse proxy is not what it answers the client, but what
/// it hands the origin — a spoofed <c>x-ms-client-principal</c> that reaches a backend is a full identity
/// forgery, and no amount of inspecting the client-facing response would reveal it. Asserting on that
/// requires an origin that actually exists, so this listens on a real socket: YARP forwards over the
/// network stack rather than through the in-memory test server, and what arrives here is exactly what a
/// deployed backend would see.
/// <para>
/// It also answers <c>/.cratis/me</c>, because AuthProxy calls it on every authenticated request to
/// resolve identity details, and a backend that refused would make every authenticated spec a 403 about
/// something else.
/// </para>
/// </remarks>
public sealed class RecordingBackend : IAsyncDisposable
{
    readonly WebApplication _app;

    RecordingBackend(WebApplication app, string baseUrl)
    {
        _app = app;
        BaseUrl = baseUrl;
    }

    /// <summary>
    /// Gets the origin's base URL, on an ephemeral loopback port.
    /// </summary>
    public string BaseUrl { get; }

    /// <summary>
    /// Gets every request the proxy has forwarded, most recent last.
    /// </summary>
    public ConcurrentQueue<ForwardedRequest> Received { get; } = new();

    /// <summary>
    /// Starts a new recording origin.
    /// </summary>
    /// <returns>The started origin.</returns>
    public static async Task<RecordingBackend> Start()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Services.AddSingleton<RecordingState>();

        var app = builder.Build();
        var state = app.Services.GetRequiredService<RecordingState>();

        app.Use(async (context, next) =>
        {
            state.Record(context);
            await next();
        });

        // AuthProxy calls this on every authenticated request to resolve identity details. Answering an
        // empty object means "authorized, nothing to add", which keeps a spec's 403 attributable to the
        // behavior under test rather than to the origin refusing.
        app.MapGet(WellKnownPaths.IdentityDetails, () => Results.Json(new { }));

        app.MapFallback(() => Results.Text("origin", "text/plain"));

        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!
            .Addresses
            .First();

        var backend = new RecordingBackend(app, address);
        state.Attach(backend.Received);

        return backend;
    }

    /// <summary>
    /// Gets the most recently forwarded request, or <see langword="null"/> when nothing was forwarded.
    /// </summary>
    /// <returns>The last forwarded request.</returns>
    public ForwardedRequest? LastRequest() => Received.LastOrDefault();

    /// <summary>
    /// Gets the most recent request forwarded to a specific path.
    /// </summary>
    /// <param name="path">The path to look for.</param>
    /// <returns>The last request to that path, or <see langword="null"/> when there was none.</returns>
    /// <remarks>
    /// An authenticated request produces two calls here — the proxy's own <c>/.cratis/me</c> identity
    /// resolution and then the forwarded request itself — so a spec that means "the request I sent" has to
    /// say which one, rather than trusting the order they happen to arrive in.
    /// </remarks>
    public ForwardedRequest? LastRequestTo(string path) =>
        Received.LastOrDefault(request => string.Equals(request.Path, path, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Gets whether anything at all was forwarded to a path.
    /// </summary>
    /// <param name="path">The path to look for.</param>
    /// <returns><see langword="true"/> when the origin saw that path; otherwise <see langword="false"/>.</returns>
    public bool ReceivedAnythingFor(string path) => LastRequestTo(path) is not null;

    /// <summary>
    /// Forgets every recorded request, so one spec's traffic cannot be read as another's.
    /// </summary>
    public void Clear() => Received.Clear();

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    /// <summary>
    /// Records requests into whichever queue the owning origin exposes.
    /// </summary>
    sealed class RecordingState
    {
        ConcurrentQueue<ForwardedRequest>? _target;

        public void Attach(ConcurrentQueue<ForwardedRequest> target) => _target = target;

        public void Record(HttpContext context) =>
            _target?.Enqueue(new ForwardedRequest(
                context.Request.Method,
                context.Request.Path.Value ?? string.Empty,
                context.Request.QueryString.Value ?? string.Empty,
                context.Request.Headers.ToDictionary(
                    header => header.Key,
                    header => header.Value.ToString(),
                    StringComparer.OrdinalIgnoreCase)));
    }
}
