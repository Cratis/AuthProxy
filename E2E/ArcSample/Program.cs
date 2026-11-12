// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using ArcSample;

// A minimal Arc application the way a customer runs one behind AuthProxy: no event sourcing, no database.
var builder = WebApplication.CreateBuilder(args);

// AuthProxy is the trusted ingress in front of this app and forwards the caller's identity in headers.
// Generated command routes live under /.cratis so one client-credentials route prefix (which scopes a bearer
// token) covers the whole Arc surface the lane drives.
builder.AddCratisArc(options =>
{
    options.TrustForwardedIdentityHeaders = true;
    options.GeneratedApis.RoutePrefix = ".cratis";
});

var app = builder.Build();
app.UseRouting();
app.UseWebSockets();
app.UseCratisArc();

app.MapGet("/", () => "arc-sample");

// The back-channel AuthProxy calls to verify client credentials (see AuthProxy "Back-channel client credentials").
var expectedSecret = app.Configuration["E2E_CLIENT_SECRET"] ?? "e2e-throwaway-secret";
app.MapPost("/.cratis/client-credentials/verify", (VerifyRequest request) =>
    string.Equals(request.ClientSecret, expectedSecret, StringComparison.Ordinal)
        ? Results.Json(new { tenant = "4f1d2c1e-6f1b-4d3b-9a46-5e2f2a7a2b10" })
        : Results.Unauthorized());

await app.RunAsync();
