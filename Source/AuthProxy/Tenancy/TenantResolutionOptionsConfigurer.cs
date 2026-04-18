// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Post-configures <see cref="C.AuthProxy"/> by binding each <see cref="C.TenantResolution.Options"/>
/// to its concrete typed options class based on the <see cref="C.TenantSourceIdentifierResolverType"/> discriminator.
/// </summary>
/// <remarks>
/// Because <see cref="C.TenantResolution.Options"/> is typed as <c>object?</c>, the standard configuration
/// binder cannot determine which concrete type to instantiate. This post-configure step reads the raw
/// <see cref="IConfiguration"/> sub-section for each resolution entry and binds it to the correct typed
/// options record, ensuring full environment-variable support and compile-time safety.
/// </remarks>
/// <param name="configuration">The application configuration used to bind strategy-specific option sub-sections.</param>
public class TenantResolutionOptionsConfigurer(IConfiguration configuration) : IPostConfigureOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public void PostConfigure(string? name, C.AuthProxy options)
    {
        var resolutionsSection = configuration.GetSection($"{C.AuthProxy.SectionKey}:TenantResolutions");

        for (var i = 0; i < options.TenantResolutions.Count; i++)
        {
            var resolution = options.TenantResolutions[i];
            var optionsSection = resolutionsSection.GetSection($"{i}:Options");

            resolution.Options = resolution.Strategy switch
            {
                C.TenantSourceIdentifierResolverType.Claim => optionsSection.Get<ClaimOptions>() ?? new ClaimOptions(),
                C.TenantSourceIdentifierResolverType.Route => optionsSection.Get<RouteOptions>() ?? new RouteOptions(),
                C.TenantSourceIdentifierResolverType.Specified => optionsSection.Get<SpecifiedOptions>() ?? new SpecifiedOptions(),
                C.TenantSourceIdentifierResolverType.Default => optionsSection.Get<DefaultOptions>() ?? new DefaultOptions(),
                _ => null
            };
        }
    }
}
