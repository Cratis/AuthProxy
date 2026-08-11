// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Writes the pages of the credential-link flow — provider selection, completion, and failure — with the
/// embedding posture the flow requires.
/// </summary>
/// <remarks>
/// The link flow is designed to run inside an <c>iframe</c> on the product's page (see
/// <see cref="C.Link.EmbedAncestors"/>): the framed selection page opens the provider leg in a separate
/// top-level window — external identity providers refuse to render framed — and the completion and failure
/// pages report back over a <c>BroadcastChannel</c> so the framed page can tell its parent the outcome.
/// Every page is served through <see cref="IErrorPageProvider"/> so a deployment can restyle it, and every
/// page carries the frame-ancestors policy resolved from configuration — none by default.
/// </remarks>
public static class LinkFlowPages
{
    /// <summary>
    /// The substitution token in the link pages that receives the JSON array of origins the framed page
    /// may post the flow's outcome to.
    /// </summary>
    public const string EmbedTargetOriginsToken = "__CRATIS_LINK_EMBED_TARGET_ORIGINS__";

    /// <summary>
    /// Writes the provider-selection page of the link flow.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static Task WriteSelection(HttpContext context) =>
        Write(context, WellKnownPageNames.LinkSelectProvider, StatusCodes.Status200OK);

    /// <summary>
    /// Writes the completion page a successful link ends on.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static Task WriteComplete(HttpContext context) =>
        Write(context, WellKnownPageNames.LinkComplete, StatusCodes.Status200OK);

    /// <summary>
    /// Writes the failure page every unsuccessful link ends on.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static Task WriteFailed(HttpContext context) =>
        Write(context, WellKnownPageNames.LinkFailed, StatusCodes.Status403Forbidden);

    static Task Write(HttpContext context, string pageName, int statusCode)
    {
        var ancestors = context.RequestServices
            .GetRequiredService<IOptionsMonitor<C.AuthProxy>>()
            .CurrentValue.Link?.EmbedAncestors ?? [];

        FrameEmbedding.Apply(context, ancestors);

        var targetOrigins = JsonSerializer.Serialize(FrameEmbedding.ResolveAncestorOrigins(context, ancestors));
        return context.RequestServices
            .GetRequiredService<IErrorPageProvider>()
            .WriteErrorPageAsync(
                context,
                pageName,
                statusCode,
                new Dictionary<string, string> { [EmbedTargetOriginsToken] = targetOrigins });
    }
}
