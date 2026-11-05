// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A loopback origin that records raw transport fields and independently verifies v1 proofs.</summary>
public sealed class ForwardedIdentityOrigin : IAsyncDisposable
{
    readonly WebApplication _app;

    ForwardedIdentityOrigin(WebApplication app, string audience, string keyId, byte[] secret)
    {
        _app = app;
        Audience = audience;
        KeyId = keyId;
        Secret = secret;
    }

    /// <summary>Gets the receiver's audience.</summary>
    public string Audience { get; }

    /// <summary>Gets the receiver's key identifier.</summary>
    public string KeyId { get; }

    /// <summary>Gets the public test-only receiver key.</summary>
    public ReadOnlyMemory<byte> Secret { get; }

    /// <summary>Gets the loopback URL.</summary>
    public string BaseUrl => _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();

    /// <summary>Gets the wire observations.</summary>
    public ConcurrentQueue<ForwardedIdentityObservation> Received { get; } = new();

    /// <summary>Gets or sets an optional redirect response for identity or tenant endpoints.</summary>
    public string? RedirectTo { get; set; }

    /// <summary>Starts a verifier-backed origin.</summary>
    /// <param name="audience">The receiver audience.</param>
    /// <param name="keyId">The receiver key identifier.</param>
    /// <param name="keyByte">The repeated public test-only key byte.</param>
    /// <returns>The running origin.</returns>
    public static async Task<ForwardedIdentityOrigin> Start(string audience, string keyId, byte keyByte)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var origin = new ForwardedIdentityOrigin(app, audience, keyId, Enumerable.Repeat(keyByte, 32).ToArray());
        app.Run(async context =>
        {
            var observation = new ForwardedIdentityObservation(
                context.Request.Method,
                context.Features.Get<IHttpRequestFeature>()!.RawTarget!,
                context.Request.Headers.ToDictionary(header => header.Key, header => header.Value.Select(value => value!).ToArray(), StringComparer.OrdinalIgnoreCase),
                false);
            var verified = ForwardedIdentityVerifier.Verify(observation, audience, keyId, origin.Secret.ToArray());
            origin.Received.Enqueue(observation with { Verified = verified });
            var hasIdentity = observation.Headers.Keys.Any(name => name.StartsWith("x-ms-client-principal", StringComparison.OrdinalIgnoreCase));
            if (hasIdentity && !verified)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            if (context.Request.Path.Value!.EndsWith(WellKnownPaths.IdentityDetails, StringComparison.Ordinal) || context.Request.Path == "/tenants")
            {
                if (origin.RedirectTo is not null)
                {
                    context.Response.Redirect(origin.RedirectTo);
                    return;
                }
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(context.Request.Path == "/tenants"
                    ? "[{\"id\":\"11111111-1111-1111-1111-111111111111\",\"name\":\"Spec Tenant\"}]"
                    : "{\"isAuthorized\":true}");
                return;
            }
            await context.Response.WriteAsync("origin");
        });
        await app.StartAsync();
        return origin;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}
