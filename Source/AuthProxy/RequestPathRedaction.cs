// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Reduces a request path to the bounded route label that may be written to a log sink.
/// </summary>
/// <remarks>
/// An invitation arrives as <c>/invite/{capability}</c>, so on a Phase-1 invitation request the request path
/// <em>is</em> a live bearer capability. Rendering a raw path into a log therefore hands that capability to
/// every sink the logs reach. Only the leading route segment is bounded by what this proxy routes rather than
/// by what a caller put in the URL, so that is all this keeps; everything after it becomes a fixed marker.
/// Collapsing the remainder also removes any caller-supplied carriage return or line feed, so a redacted
/// label cannot forge a log line either.
/// </remarks>
internal static class RequestPathRedaction
{
    /// <summary>
    /// The marker written in place of everything below the leading route segment.
    /// </summary>
    internal const string Marker = "[redacted]";

    /// <summary>
    /// Redacts a request path down to its leading route segment.
    /// </summary>
    /// <param name="path">The request path to redact.</param>
    /// <returns>The leading route segment, with any remainder replaced by <see cref="Marker"/>.</returns>
    internal static string Redact(PathString path)
    {
        var value = path.Value;
        if (string.IsNullOrEmpty(value))
        {
            return "/";
        }

        var separator = value.IndexOf('/', 1);

        return separator < 0
            ? Sanitize(value)
            : $"{Sanitize(value[..separator])}/{Marker}";
    }

    static string Sanitize(string value) => value.Replace('\r', '_').Replace('\n', '_');
}
