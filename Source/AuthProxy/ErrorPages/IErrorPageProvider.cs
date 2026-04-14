// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ErrorPages;

/// <summary>
/// Defines a provider that writes a named error page into an HTTP response.
/// </summary>
public interface IErrorPageProvider
{
    /// <summary>
    /// Writes the content of the named error page into the response.
    /// Sets <see cref="HttpResponse.StatusCode"/> and <c>Content-Type: text/html</c> before sending.
    /// If the named page does not exist a minimal inline HTML fallback is written instead.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="pageName">The file name of the page, e.g. <c>"404.html"</c> or <c>"invitation-expired.html"</c>.</param>
    /// <param name="statusCode">The HTTP status code to set on the response.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous write operation.</returns>
    Task WriteErrorPageAsync(HttpContext context, string pageName, int statusCode);
}
