// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Extension methods for registering tenancy services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class TenancyServiceCollectionExtensions
{
    /// <summary>
    /// Registers all tenant resolution strategies and the <see cref="ITenantResolver"/>.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddTenancy(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<ISourceIdentifierStrategy, HostSourceIdentifierStrategy>();
        builder.Services.AddSingleton<ISourceIdentifierStrategy, ClaimSourceIdentifierStrategy>();
        builder.Services.AddSingleton<ISourceIdentifierStrategy, RouteSourceIdentifierStrategy>();
        builder.Services.AddSingleton<ISourceIdentifierStrategy, SpecifiedSourceIdentifierStrategy>();
        builder.Services.AddSingleton<ITenantResolver, TenantResolver>();

        return builder;
    }
}
