// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ErrorPages;

/// <summary>
/// Serves custom error pages from a configurable directory on disk.
/// </summary>
/// <remarks>
/// Page resolution order:
/// <list type="number">
///   <item>The directory configured in <see cref="C.AuthProxy.PagesPath"/> (when set and the directory exists).</item>
///   <item>A <c>Pages</c> directory co-located with the application's content root.</item>
/// </list>
/// If neither location contains the requested page, a minimal inline HTML fallback is written.
/// </remarks>
/// <param name="environment">The web host environment, used to locate the application content root.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
public class ErrorPageProvider(IWebHostEnvironment environment, IOptionsMonitor<C.AuthProxy> config) : IErrorPageProvider
{
    /// <inheritdoc/>
    public async Task WriteErrorPageAsync(HttpContext context, string pageName, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "text/html; charset=utf-8";

        var pagePath = ResolvePage(pageName);
        if (pagePath is not null)
        {
            await context.Response.SendFileAsync(pagePath);
            return;
        }

        await context.Response.WriteAsync(
            "<!DOCTYPE html>" +
            "<html lang=\"en\">" +
            "<head><meta charset=\"utf-8\"><title>Error " + statusCode + "</title></head>" +
            "<body><h1>Error " + statusCode + "</h1></body>" +
            "</html>");
    }

    string? ResolvePage(string pageName)
    {
        var configuredPath = config.CurrentValue.PagesPath;
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            var configuredPage = Path.Combine(configuredPath, pageName);
            if (File.Exists(configuredPage))
            {
                return configuredPage;
            }
        }

        var defaultPage = Path.Combine(environment.ContentRootPath, "Pages", pageName);
        if (File.Exists(defaultPage))
        {
            return defaultPage;
        }

        return null;
    }
}
