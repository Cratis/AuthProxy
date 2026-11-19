// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Places the public path boundary ahead of all other request handlers.
/// </summary>
public static class DeniedPathExtensions
{
    /// <summary>
    /// Adds the guard once. Hosts embedding AuthProxy must call this before their own middleware.
    /// </summary>
    /// <param name="app">The application.</param>
    /// <returns>The application for chaining.</returns>
    public static WebApplication UseDeniedPathPrefixes(this WebApplication app)
    {
        var properties = ((IApplicationBuilder)app).Properties;
        if (properties.TryAdd(typeof(DeniedPathMiddleware).FullName!, true))
        {
            app.UseMiddleware<DeniedPathMiddleware>();
        }

        return app;
    }
}
