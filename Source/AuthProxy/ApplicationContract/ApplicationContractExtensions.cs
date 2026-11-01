// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract;

/// <summary>
/// Extension methods for adding the application configuration contract to a host.
/// </summary>
public static class ApplicationContractExtensions
{
    /// <summary>
    /// Adds the settings the application configuration contract produces on top of the existing configuration.
    /// </summary>
    /// <param name="builder">The builder to add to.</param>
    /// <returns>The same builder for chaining.</returns>
    /// <exception cref="ApplicationContractException">Thrown when the contract is incomplete or invalid.</exception>
    public static WebApplicationBuilder AddApplicationContract(this WebApplicationBuilder builder)
    {
        var settings = ApplicationContractTranslator.Translate(builder.Configuration);
        if (settings.Count > 0)
        {
            builder.Configuration.AddInMemoryCollection(settings);
        }

        return builder;
    }
}
