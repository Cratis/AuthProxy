// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Extension methods for registering credential-linking services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class LinksServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="ILinkSubjectExchanger"/> used by the session-preserving link flow.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddLinks(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<ILinkSubjectExchanger, LinkSubjectExchanger>();

        return builder;
    }
}
