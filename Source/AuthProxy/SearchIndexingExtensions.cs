// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Places search-index exclusion headers ahead of all proxy-owned responses.
/// </summary>
public static class SearchIndexingExtensions
{
    const string RegistrationKey = "Cratis.AuthProxy.SearchIndexingHeaders";

    /// <summary>
    /// Adds the opt-in response header once, including when management and ingress share a pipeline.
    /// </summary>
    /// <param name="app">The application to configure.</param>
    /// <returns>The same application for chaining.</returns>
    public static WebApplication UseSearchIndexingHeaders(this WebApplication app)
    {
        var properties = ((IApplicationBuilder)app).Properties;
        if (properties.ContainsKey(RegistrationKey))
        {
            return app;
        }

        properties[RegistrationKey] = true;
        app.Use(async (context, next) =>
        {
            if (context.RequestServices.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue.SearchIndexing.Exclude)
            {
                context.Response.OnStarting(() =>
                {
                    // YARP copies the upstream headers before starting the response. Let the application's
                    // explicit policy win, and supply ours only if it did not state one.
                    context.Response.Headers.TryAdd("X-Robots-Tag", "noindex, nofollow");
                    return Task.CompletedTask;
                });
            }

            await next(context);
        });

        return app;
    }
}
