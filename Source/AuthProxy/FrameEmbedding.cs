// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Declares whether a page the proxy serves may be embedded in a frame, via
/// <c>Content-Security-Policy: frame-ancestors</c> (with <c>X-Frame-Options</c> for the deny case).
/// </summary>
/// <remarks>
/// The proxy's own pages fall in two classes. Sign-in pages (provider selection, invitation selection)
/// must never render framed — a framed login is clickjacking bait — so they always
/// <see cref="Deny"/>. The credential-link pages exist to be framed by the product
/// (see <see cref="Configuration.Link.EmbedAncestors"/>), so they <see cref="Apply"/> the configured
/// ancestor list — which is empty, and therefore a deny, unless a deployment opts in. Nothing here touches
/// proxied application responses; the application keeps authority over its own headers.
/// </remarks>
public static class FrameEmbedding
{
    /// <summary>
    /// The configuration value naming the proxy's own origin as an allowed ancestor — the common case,
    /// where the product is served through the proxy itself.
    /// </summary>
    public const string SelfAncestor = "self";

    /// <summary>
    /// Forbids framing the current response outright.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    public static void Deny(HttpContext context)
    {
        context.Response.Headers.XFrameOptions = "DENY";
        context.Response.Headers.ContentSecurityPolicy = "frame-ancestors 'none'";
    }

    /// <summary>
    /// Applies the configured allowed frame ancestors to the current response — a deny when none are
    /// configured.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="ancestors">The configured allowed ancestor origins; <c>"self"</c> names the proxy's own origin.</param>
    public static void Apply(HttpContext context, IEnumerable<string> ancestors)
    {
        var sources = ancestors
            .Where(ancestor => !string.IsNullOrWhiteSpace(ancestor))
            .Select(ancestor => string.Equals(ancestor, SelfAncestor, StringComparison.OrdinalIgnoreCase) ? "'self'" : ancestor.Trim())
            .ToArray();

        if (sources.Length == 0)
        {
            Deny(context);
            return;
        }

        // X-Frame-Options cannot express an origin allow-list and would override the policy in browsers
        // that honor it over CSP, so only the CSP header is sent when embedding is allowed.
        context.Response.Headers.ContentSecurityPolicy = $"frame-ancestors {string.Join(' ', sources)}";
    }

    /// <summary>
    /// Resolves the configured ancestors to the concrete origins a framed page may post messages to,
    /// translating <c>"self"</c> to the origin of the current request.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="ancestors">The configured allowed ancestor origins.</param>
    /// <returns>The concrete target origins.</returns>
    public static IReadOnlyList<string> ResolveAncestorOrigins(HttpContext context, IEnumerable<string> ancestors) =>
        [.. ancestors
            .Where(ancestor => !string.IsNullOrWhiteSpace(ancestor))
            .Select(ancestor => string.Equals(ancestor, SelfAncestor, StringComparison.OrdinalIgnoreCase)
                ? $"{context.Request.Scheme}://{context.Request.Host}"
                : ancestor.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)];
}
