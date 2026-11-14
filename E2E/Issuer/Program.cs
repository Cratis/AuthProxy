// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using E2E.Issuer;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
var introspectionSecret = builder.Configuration["E2E_INTROSPECTION_SECRET"] ?? throw new InvalidOperationException("Missing throwaway introspection secret");
using var issuer = new LocalIssuer();
var app = builder.Build();
app.Use(async (context, next) =>
{
    await next(context);
    // Issuer paths are fixed test-control names; no token, body, header or query is logged.
    Console.WriteLine($"ISSUER: {context.Request.Path} HTTP {context.Response.StatusCode}");
});
app.MapGet("/health", () => Results.Ok());
app.MapGet("/.well-known/oauth-authorization-server", () => Results.Json(new { issuer = LocalIssuer.Address, jwks_uri = $"{LocalIssuer.Address}/jwks", token_endpoint = $"{LocalIssuer.Address}/mint/person" }));
app.MapGet("/jwks", () => Results.Json(issuer.Jwks()));
app.MapPost("/mint/{scenario}", (string scenario) => Results.Json(new { access_token = issuer.Mint(scenario) }));
app.MapPost("/introspect", async (HttpRequest request) =>
{
    var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"e2e-introspection:{introspectionSecret}"));
    if (request.Headers.Authorization.ToString() != expected) return Results.StatusCode(401);
    if (issuer.Outage) return Results.StatusCode(503);
    var form = await request.ReadFormAsync();
    return Results.Json(issuer.Introspect(form["token"].ToString()));
});
app.MapPost("/revoke", async (HttpRequest request) => { issuer.Revoke((await request.ReadFormAsync())["token"].ToString()); return Results.Ok(); });
app.MapPost("/outage/{enabled:bool}", (bool enabled) => { issuer.Outage = enabled; return Results.Ok(); });
await app.RunAsync();
