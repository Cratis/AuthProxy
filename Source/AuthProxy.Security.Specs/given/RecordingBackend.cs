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
    /// <summary>
    /// The path AuthProxy is pointed at for sign-in notifications, so their bodies can be read back.
    /// </summary>
    /// <remarks>
    /// A sign-in notification is the one thing about a request that leaves the proxy as a body rather than as
    /// headers, and its <c>ipAddress</c> and <c>location</c> are the audit record a forged forwarded header
    /// would poison. Reading it here means asserting on what the application would actually have been told.
    /// </remarks>
    public const string SignInNotificationPath = "/.security-spec/sign-ins";

    readonly WebApplication _app;
    readonly IdentityResponder _identityResponder;

    RecordingBackend(WebApplication app, string baseUrl, IdentityResponder identityResponder)
    {
        _app = app;
        _identityResponder = identityResponder;
        BaseUrl = baseUrl;
    }

    /// <summary>
    /// Gets the origin's base URL, on an ephemeral loopback port.
    /// </summary>
    public string BaseUrl { get; }

    /// <summary>
    /// Gets or sets what the origin answers on the identity endpoint.
    /// </summary>
    /// <remarks>
    /// Settable because a deployment that treats <c>/.cratis/me</c> as an authorization decision has to be
    /// shown failing and then recovering, and the whole point of asserting end to end is that the failure
    /// arrives the way a real one would — over a socket, from an origin that genuinely answered that way.
    /// The default answers an empty object, which is what every other security spec's deployment expects.
    /// </remarks>
    public Func<IResult> IdentityResponse
    {
        get => _identityResponder.Respond;
        set => _identityResponder.Respond = value;
    }

    /// <summary>
    /// Gets every request the proxy has forwarded, most recent last.
    /// </summary>
    public ConcurrentQueue<ForwardedRequest> Received { get; } = new();

    /// <summary>
    /// Gets the body of every sign-in notification the proxy has posted, most recent last.
    /// </summary>
    public ConcurrentQueue<string> SignInNotifications { get; } = new();

    /// <summary>
    /// Gets the absolute URL AuthProxy should be configured to post sign-in notifications to.
    /// </summary>
    public string SignInNotificationUrl => $"{BaseUrl.TrimEnd('/')}{SignInNotificationPath}";

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
        builder.Services.AddSingleton<IdentityResponder>();

        var app = builder.Build();
        var state = app.Services.GetRequiredService<RecordingState>();
        var identityResponder = app.Services.GetRequiredService<IdentityResponder>();

        app.Use(async (context, next) =>
        {
            state.Record(context);
            await next();
        });

        // AuthProxy calls this on every authenticated request to resolve identity details. Answering an
        // empty object means "authorized, nothing to add" to a best-effort deployment, which keeps a spec's
        // 403 attributable to the behavior under test rather than to the origin refusing.
        app.MapGet(WellKnownPaths.IdentityDetails, (IdentityResponder responder) => responder.Respond());

        app.MapPost(SignInNotificationPath, async (HttpContext context, RecordingState recording) =>
        {
            using var reader = new StreamReader(context.Request.Body);
            recording.RecordSignIn(await reader.ReadToEndAsync());

            return Results.Ok();
        });

        app.MapFallback(() => Results.Text("origin", "text/plain"));

        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!
            .Addresses
            .First();

        var backend = new RecordingBackend(app, address, identityResponder);
        state.Attach(backend.Received, backend.SignInNotifications);

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
    /// Gets the body of the most recent sign-in notification, or <see langword="null"/> when none was posted.
    /// </summary>
    /// <returns>The last sign-in notification body.</returns>
    public string? LastSignInNotification() => SignInNotifications.LastOrDefault();

    /// <summary>
    /// Forgets every recorded request, so one spec's traffic cannot be read as another's.
    /// </summary>
    public void Clear()
    {
        Received.Clear();
        SignInNotifications.Clear();
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    /// <summary>
    /// Holds what the origin currently answers on the identity endpoint.
    /// </summary>
    sealed class IdentityResponder
    {
        public Func<IResult> Respond { get; set; } = () => Results.Json(new { });
    }

    /// <summary>
    /// Records requests into whichever queue the owning origin exposes.
    /// </summary>
    sealed class RecordingState
    {
        ConcurrentQueue<ForwardedRequest>? _target;
        ConcurrentQueue<string>? _signInNotifications;

        public void Attach(ConcurrentQueue<ForwardedRequest> target, ConcurrentQueue<string> signInNotifications)
        {
            _target = target;
            _signInNotifications = signInNotifications;
        }

        public void RecordSignIn(string body) => _signInNotifications?.Enqueue(body);

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
