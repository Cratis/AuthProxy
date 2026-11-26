// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Net;
using Cratis.AuthProxy.ErrorPages;

namespace Cratis.AuthProxy.Code;

/// <summary>
/// Writes the two pages of the code sign-in, which a deployment can replace like any other well-known page.
/// </summary>
static class CodePages
{
    /// <summary>The token for: The address the forms post back to.</summary>
    internal const string Action = "__CRATIS_CODE_ACTION__";

    /// <summary>The token for: The protected sign-in state.</summary>
    internal const string State = "__CRATIS_CODE_STATE__";

    /// <summary>The token for: The provider's display name.</summary>
    internal const string Provider = "__CRATIS_CODE_PROVIDER__";

    /// <summary>The token for: The e-mail address, or what was typed.</summary>
    internal const string Address = "__CRATIS_CODE_ADDRESS__";

    /// <summary>The token for: `readonly` when an invitation fixes the address.</summary>
    internal const string AddressLocked = "__CRATIS_CODE_ADDRESS_LOCKED__";

    /// <summary>The token for: The identifier of the issued challenge.</summary>
    internal const string Challenge = "__CRATIS_CODE_CHALLENGE__";

    /// <summary>The token for: The number of digits in a code.</summary>
    internal const string Length = "__CRATIS_CODE_LENGTH__";

    /// <summary>The token for: What went wrong, as a short code the page can word.</summary>
    internal const string Error = "__CRATIS_CODE_ERROR__";

    /// <summary>
    /// Writes the address page.
    /// </summary>
    /// <param name="context">The request.</param>
    /// <param name="pages">The page provider.</param>
    /// <param name="action">Where the form posts.</param>
    /// <param name="state">The protected sign-in state.</param>
    /// <param name="provider">The provider's display name.</param>
    /// <param name="address">The address to show.</param>
    /// <param name="locked">Whether the address cannot be changed.</param>
    /// <param name="error">An error code to show, or empty.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal static Task WriteEmail(HttpContext context, IErrorPageProvider pages, string action, string state, string provider, string address, bool locked, string error) =>
        Write(context, pages, WellKnownPageNames.CodeEmail, new()
        {
            [Action] = Encode(action),
            [State] = Encode(state),
            [Provider] = Encode(provider),
            [Address] = Encode(address),
            [AddressLocked] = locked ? "readonly" : string.Empty,
            [Error] = Encode(error),
        });

    /// <summary>
    /// Writes the code page.
    /// </summary>
    /// <param name="context">The request.</param>
    /// <param name="pages">The page provider.</param>
    /// <param name="action">Where the form posts.</param>
    /// <param name="state">The protected sign-in state.</param>
    /// <param name="provider">The provider's display name.</param>
    /// <param name="address">The address the code was sent to.</param>
    /// <param name="challenge">The challenge the code belongs to.</param>
    /// <param name="length">The number of digits in a code.</param>
    /// <param name="error">An error code to show, or empty.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal static Task WriteVerify(HttpContext context, IErrorPageProvider pages, string action, string state, string provider, string address, string challenge, int length, string error) =>
        Write(context, pages, WellKnownPageNames.CodeVerify, new()
        {
            [Action] = Encode(action),
            [State] = Encode(state),
            [Provider] = Encode(provider),
            [Address] = Encode(address),
            [Challenge] = Encode(challenge),
            [Length] = length.ToString(CultureInfo.InvariantCulture),
            [Error] = Encode(error),
        });

    /// <summary>
    /// Writes a page that is never framed or cached.
    /// </summary>
    /// <param name="context">The request.</param>
    /// <param name="pages">The page provider.</param>
    /// <param name="page">The page name.</param>
    /// <param name="substitutions">The token values.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    static Task Write(HttpContext context, IErrorPageProvider pages, string page, Dictionary<string, string> substitutions)
    {
        FrameEmbedding.Deny(context);
        context.Response.Headers.CacheControl = "no-store";
        return pages.WriteErrorPageAsync(context, page, StatusCodes.Status200OK, substitutions);
    }

    /// <summary>
    /// Encodes a value so it cannot break the page or be read as another token.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The encoded value.</returns>
    static string Encode(string value) =>
        WebUtility.HtmlEncode(value)
            .Replace("{", "&#123;", StringComparison.Ordinal)
            .Replace("}", "&#125;", StringComparison.Ordinal)
            .Replace("_", "&#95;", StringComparison.Ordinal);
}
