// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Serves the opt-in robots file without authentication, tenant resolution or forwarding.
/// </summary>
/// <param name="next">The next middleware.</param>
/// <param name="configuration">The proxy configuration.</param>
public class SearchIndexingMiddleware(RequestDelegate next, IOptionsMonitor<C.AuthProxy> configuration)
{
    const string Robots = "User-agent: *\nDisallow: /\n";

    /// <summary>
    /// Answers GET and HEAD requests for the robots file when exclusion is enabled.
    /// </summary>
    /// <param name="context">The current request.</param>
    /// <returns>The asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        if (configuration.CurrentValue.SearchIndexing.Exclude
            && context.Request.Path.Equals("/robots.txt", StringComparison.Ordinal)
            && (HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method)))
        {
            context.Response.ContentType = "text/plain; charset=utf-8";
            context.Response.ContentLength = Robots.Length;
            if (HttpMethods.IsGet(context.Request.Method))
            {
                await context.Response.WriteAsync(Robots, context.RequestAborted);
            }

            return;
        }

        await next(context);
    }
}
