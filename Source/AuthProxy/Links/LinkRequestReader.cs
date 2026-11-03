// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Reads a <see cref="LinkRequest"/> from an HTTP request.
/// </summary>
/// <remarks>
/// Starting a challenge changes state, so it is only ever done for a confirmed form post: the values then come
/// from the form and the post must carry a valid antiforgery cookie and token. Any other request reads the query
/// string and is only ever answered with a page.
/// </remarks>
internal static class LinkRequestReader
{
    /// <summary>
    /// Reads the request values.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="provider">The provider scheme taken from the path, empty for the bare link path.</param>
    /// <returns>The request, or <see langword="null"/> when the post is not valid or carries no link token.</returns>
    public static async Task<LinkRequest?> Read(HttpContext context, string provider)
    {
        var confirmed = provider.Length > 0 && HttpMethods.IsPost(context.Request.Method);
        if (confirmed && !await ProxyAntiforgery.IsValidAsync(context))
        {
            return null;
        }

        Func<string, string?> value = confirmed
            ? name => context.Request.Form[name].FirstOrDefault()
            : name => context.Request.Query[name].FirstOrDefault();
        var token = value("token");

        return string.IsNullOrWhiteSpace(token)
            ? null
            : new LinkRequest(provider, token, value("returnUrl"), confirmed);
    }
}
