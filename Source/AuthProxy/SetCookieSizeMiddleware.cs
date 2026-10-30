// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy;

/// <summary>
/// Warns when the <c language="text">Set-Cookie</c> headers on a response are large enough to risk a reverse proxy's header buffer.
/// </summary>
/// <remarks>
/// A sign-in callback can set the session, identity, authorization and tenant cookies and clear several leftovers in
/// one response. ingress-nginx answers <c language="text">502</c> when the response header passes its
/// <c language="text">proxy-buffer-size</c> (4k by default), and the user only sees the failure, never the cause. The warning
/// names each cookie and its size, never a value, so an operator can see which cookie to shrink or what buffer to configure.
/// </remarks>
/// <param name="next">The next middleware.</param>
/// <param name="logger">The logger.</param>
public class SetCookieSizeMiddleware(RequestDelegate next, ILogger<SetCookieSizeMiddleware> logger)
{
    /// <summary>
    /// The combined <c language="text">Set-Cookie</c> size, in bytes, above which a response is reported. A 4k header buffer also holds
    /// the status line and every other header, so this leaves a little room for those.
    /// </summary>
    internal const int WarningThreshold = 3584;

    /// <summary>
    /// Registers the size check to run as the response starts, then continues the pipeline.
    /// </summary>
    /// <param name="context">The current request.</param>
    /// <returns>The asynchronous operation.</returns>
    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            Check(context);
            return Task.CompletedTask;
        });

        return next(context);
    }

    /// <summary>
    /// Measures the <c language="text">Set-Cookie</c> headers of a response.
    /// </summary>
    /// <param name="headers">The response headers.</param>
    /// <param name="total">The combined size of the headers, in bytes.</param>
    /// <param name="cookies">Each cookie's name and header length, without its value.</param>
    /// <returns><see langword="true"/> when the response sets at least one cookie.</returns>
    internal static bool TryMeasure(IHeaderDictionary headers, out int total, out string cookies)
    {
        total = 0;
        cookies = string.Empty;

        if (!headers.TryGetValue(HeaderNames.SetCookie, out var values) || values.Count == 0)
        {
            return false;
        }

        var parts = new List<string>(values.Count);
        foreach (var value in values)
        {
            var header = value ?? string.Empty;
            var separator = header.IndexOf('=', StringComparison.Ordinal);
            var name = separator < 0 ? header : header[..separator];
            total += HeaderNames.SetCookie.Length + 2 + header.Length + 2;
            parts.Add($"{name} ({header.Length})");
        }

        cookies = string.Join(", ", parts);
        return true;
    }

    void Check(HttpContext context)
    {
        if (TryMeasure(context.Response.Headers, out var total, out var cookies) && total > WarningThreshold)
        {
            logger.SetCookieHeadersLarge(RequestPathRedaction.Redact(context.Request.Path), total, WarningThreshold, cookies);
        }
    }
}
