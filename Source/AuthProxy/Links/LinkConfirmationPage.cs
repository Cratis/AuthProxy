// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.ErrorPages;

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Writes the page that asks the user to confirm linking a provider.
/// </summary>
internal static class LinkConfirmationPage
{
    /// <summary>
    /// Writes the confirmation page for a link request. Never framed; its form posts back to the provider's path.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="request">The request being confirmed.</param>
    /// <param name="providerName">The display name of the provider.</param>
    /// <returns>A task that completes when the page has been written.</returns>
    public static Task Write(HttpContext context, LinkRequest request, string providerName)
    {
        FrameEmbedding.Deny(context);
        return context.RequestServices
            .GetRequiredService<IErrorPageProvider>()
            .WriteErrorPageAsync(
                context,
                WellKnownPageNames.LinkConfirm,
                StatusCodes.Status200OK,
                new Dictionary<string, string>
                {
                    [LinkConfirmationTokens.Action] = Encode($"{WellKnownPaths.Link}/{request.Provider}"),
                    [LinkConfirmationTokens.Provider] = Encode(providerName),
                    [LinkConfirmationTokens.Token] = Encode(request.Token),
                    [LinkConfirmationTokens.ReturnUrl] = Encode(request.ReturnUrl ?? string.Empty),
                    [LinkConfirmationTokens.FieldName] = WebUtility.HtmlEncode(ProxyAntiforgery.FormFieldName),
                    [LinkConfirmationTokens.RequestToken] = Encode(ProxyAntiforgery.IssueRequestToken(context)),
                });
    }

    /// <summary>
    /// Encodes a value for substitution into a template that is itself scanned for tokens, so the characters a
    /// token is made of are encoded as well.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The encoded value.</returns>
    static string Encode(string value) =>
        WebUtility.HtmlEncode(value)
            .Replace("{", "&#123;", StringComparison.Ordinal)
            .Replace("}", "&#125;", StringComparison.Ordinal)
            .Replace("_", "&#95;", StringComparison.Ordinal);
}
