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
/// A stand-in RFC 7662 introspection endpoint on loopback, answering per token as a spec scripts it and recording
/// exactly what AuthProxy sent.
/// </summary>
public sealed class StubIntrospectionEndpoint : IAsyncDisposable
{
    /// <summary>The path of the endpoint.</summary>
    public const string Path = "/connect/introspect";

    /// <summary>The path of a second endpoint, with its own counter, used by a route that caches answers.</summary>
    public const string CachedPath = "/connect/introspect-cached";

    /// <summary>The client id AuthProxy authenticates as.</summary>
    public const string ClientId = "authproxy-resource-server";

    /// <summary>The client secret AuthProxy authenticates with. Not a real credential.</summary>
    public const string ClientSecret = "spec-only-introspection-secret";

    readonly WebApplication _app;
    readonly ConcurrentDictionary<string, string> _answers = new(StringComparer.Ordinal);
    readonly ConcurrentDictionary<string, int> _calls = new(StringComparer.Ordinal);
    readonly ConcurrentQueue<CapturedIntrospection> _captured = new();

    StubIntrospectionEndpoint(WebApplication app, string baseUrl)
    {
        _app = app;
        BaseUrl = baseUrl;
    }

    /// <summary>
    /// Gets the base URL, without a trailing slash.
    /// </summary>
    public string BaseUrl { get; }

    /// <summary>
    /// Gets or sets a status the endpoint answers every call with, instead of an answer for the token.
    /// </summary>
    public int? FailWith { get; set; }

    /// <summary>
    /// Gets or sets whether the endpoint accepts a call and never answers it.
    /// </summary>
    public bool Hang { get; set; }

    /// <summary>
    /// Gets or sets a body to answer with at status 200, instead of an answer for the token.
    /// </summary>
    public string? RawBody { get; set; }

    /// <summary>
    /// Gets every call received, most recent last.
    /// </summary>
    public IReadOnlyCollection<CapturedIntrospection> Captured => _captured;

    /// <summary>
    /// Starts a new endpoint.
    /// </summary>
    /// <returns>The started endpoint.</returns>
    public static async Task<StubIntrospectionEndpoint> Start()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        StubIntrospectionEndpoint? stub = null;

        app.MapPost(Path, context => stub!.Answer(context));
        app.MapPost(CachedPath, context => stub!.Answer(context));
        app.MapGet("/redirect", () => Results.Redirect("/connect/introspect"));

        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        return stub = new StubIntrospectionEndpoint(app, address.TrimEnd('/'));
    }

    /// <summary>
    /// Scripts the answer for a token.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="json">The JSON body to answer with.</param>
    public void Script(string token, string json) => _answers[token] = json;

    /// <summary>
    /// Scripts a token as active, with the claims the answer may carry beyond <c language="text">active</c>.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <param name="extra">Additional JSON members, without a leading comma.</param>
    public void Activate(string token, string? extra = null) =>
        Script(token, extra is null ? """{"active":true}""" : $$"""{"active":true,{{extra}}}""");

    /// <summary>
    /// Scripts a token as revoked.
    /// </summary>
    /// <param name="token">The token.</param>
    public void Revoke(string token) => Script(token, """{"active":false}""");

    /// <summary>
    /// Gets how many calls a path has received.
    /// </summary>
    /// <param name="path">The endpoint path.</param>
    /// <returns>The number of calls.</returns>
    public int CallsTo(string path) => _calls.GetValueOrDefault(path);

    /// <summary>
    /// Forgets recorded calls and resets the failure modes, keeping scripted answers.
    /// </summary>
    public void Reset()
    {
        _captured.Clear();
        _calls.Clear();
        FailWith = null;
        Hang = false;
        RawBody = null;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }

    async Task Answer(HttpContext context)
    {
        var result = await Respond(context);
        await result.ExecuteAsync(context);
    }

    async Task<IResult> Respond(HttpContext context)
    {
        var path = context.Request.Path.Value!;
        _calls.AddOrUpdate(path, 1, (_, count) => count + 1);
        var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync() : null;
        var token = form?["token"].ToString() ?? string.Empty;
        _captured.Enqueue(new CapturedIntrospection(
            context.Request.Method,
            path,
            context.Request.QueryString.Value ?? string.Empty,
            context.Request.ContentType,
            form?.Keys.Order(StringComparer.Ordinal).ToArray() ?? [],
            token,
            context.Request.Headers.Authorization.ToString(),
            context.Request.Headers.Keys.ToArray()));

        if (Hang)
        {
            await Task.Delay(Timeout.Infinite, context.RequestAborted);
        }

        if (FailWith is { } status)
        {
            return Results.StatusCode(status);
        }

        if (RawBody is { } raw)
        {
            return Results.Text(raw, "application/json");
        }

        return Results.Text(_answers.GetValueOrDefault(token, """{"active":false}"""), "application/json");
    }
}
