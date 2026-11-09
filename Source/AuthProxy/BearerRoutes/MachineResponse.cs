// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Writes the machine-readable body of a bearer-route refusal.
/// </summary>
/// <remarks>
/// The body is a fixed JSON document built from a constant code, never from request or token material, so it can
/// neither carry markup nor reveal why a credential was refused.
/// </remarks>
static class MachineResponse
{
    const string ContentType = "application/json";

    /// <summary>
    /// Sets the status and writes a JSON object holding the error code; a <c language="text">HEAD</c> request gets the headers only.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="statusCode">The status code.</param>
    /// <param name="code">A constant error code made of lowercase letters and underscores.</param>
    internal static void Write(HttpContext context, int statusCode, string code)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = ContentType;
        if (HttpMethods.IsHead(context.Request.Method))
        {
            return;
        }

        var body = Encoding.UTF8.GetBytes("{\"error\":\"" + code + "\"}");
        context.Response.ContentLength = body.Length;
        var writer = context.Response.BodyWriter;
        body.CopyTo(writer.GetSpan(body.Length));
        writer.Advance(body.Length);
    }
}
