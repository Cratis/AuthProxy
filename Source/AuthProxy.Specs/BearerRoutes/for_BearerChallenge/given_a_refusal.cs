// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerChallenge;

/// <summary>
/// Shared setup for specs that write a bearer-route refusal and read it back.
/// </summary>
public abstract class given_a_refusal : Specification
{
    protected const string MetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/mcp";

    protected static ResolvedBearerRoute Route(BearerProfile profile, string? resourceKey = null, string[]? scopes = null) =>
        new(
            "api",
            "https://backend.example.test",
            "/mcp",
            [],
            new C.BearerRoute { PathPrefix = "/mcp", RequiredScopes = scopes ?? [] },
            profile == BearerProfile.PatOnly ? null : new Uri(MetadataUrl),
            null,
            profile,
            resourceKey);

    protected static async Task<(HttpContext Context, string Body)> Write(
        BearerTokenValidationStatus status,
        ResolvedBearerRoute route,
        string method = "GET")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        var stream = new MemoryStream();
        context.Response.Body = stream;
        var validation = BearerTokenValidation.Refused(status, "reason that must never reach the caller");
        BearerChallenge.Write(context, validation, route);
        await context.Response.BodyWriter.FlushAsync();
        return (context, Encoding.UTF8.GetString(stream.ToArray()));
    }
}
