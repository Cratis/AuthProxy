// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using E2E.OAuthGrantReceiver;
using Microsoft.AspNetCore.Http.Features;

if (args.Contains("--self-test", StringComparer.Ordinal))
{
    Conformance.Run();
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
var issuer = "https://issuer:8443";
using var client = new HttpClient();
var admission = new GrantAdmission(File.ReadAllText("/run/envelope/public.pem"), issuer, new(client, issuer));
var checks = new HostileChecks(admission);
var app = builder.Build();
app.MapGet("/health", () => Results.Ok());
var received = 0;
app.MapGet("/test/count", () => Volatile.Read(ref received));
app.MapPost("/test/hostile", async (HttpRequest request) =>
{
    using var document = await JsonDocument.ParseAsync(request.Body);
    return Results.Json(await checks.Run(document.RootElement.GetProperty("token").GetString()!));
});
app.MapGet("/.well-known/oauth-protected-resource/mcp", () => Results.Json(new { resource = "https://grant.local/mcp", authorization_servers = new[] { issuer } }));
Func<HttpContext, string?, Task<IResult>> handler = async (context, path) =>
{
    _ = path;
    Interlocked.Increment(ref received);
    try
    {
        var headers = context.Request.Headers.SelectMany(pair => pair.Value.Select(value => new Header(pair.Key, value!))).ToArray();
        var target = context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? throw new Rejected("raw-target");
        await admission.Admit(context.Request.Method, target, headers);
        checks.Remember(context.Request.Method, target, headers);
        return context.Request.Path.StartsWithSegments("/mcp")
            ? await McpCapability.Respond(context.Request)
            : Results.Json(McpCapability.Evidence());
    }
    catch (Exception error) when (ReceiverErrors.IsRejection(error))
    {
        // Fixed contract-rejection labels or exception type names, never token/header values.
        Console.WriteLine($"REJECT: {(error is Rejected ? error.Message : error.GetType().Name)}");
        return Results.StatusCode(401);
    }
};
app.MapMethods("/grants/{**path}", ["GET", "POST"], handler);
app.MapMethods("/mcp/{**path}", ["GET", "POST"], handler);
await app.RunAsync();
