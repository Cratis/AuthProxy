// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Extension methods for registering bearer routes.
/// </summary>
public static class BearerRouteServiceCollectionExtensions
{
    /// <summary>
    /// The timeout for reading an issuer's metadata document or JWKS.
    /// </summary>
    public static readonly TimeSpan MetadataTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Registers the services bearer routes need. Registering them changes nothing for a deployment that
    /// declares no bearer route.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    /// <remarks>
    /// The bearer-route forwarder uses the reverse proxy's forwarder, client factory and transform builder, which
    /// the reverse-proxy registration provides; they are resolved when the pipeline is built, not here.
    /// </remarks>
    public static WebApplicationBuilder AddBearerRoutes(this WebApplicationBuilder builder)
    {
        builder.Services.AddHttpClient(BearerRouteDefaults.MetadataHttpClientName, client => client.Timeout = MetadataTimeout);
        builder.Services.AddSingleton<IBearerIssuerMetadata, BearerIssuerMetadata>();
        builder.Services.AddSingleton<IBearerTokenValidator, BearerTokenValidator>();
        builder.Services.AddSingleton<IBearerRouteForwarder, BearerRouteForwarder>();
        builder.Services.AddSingleton<IValidateOptions<C.AuthProxy>, BearerRouteConfigurationValidator>();
        builder.Services.AddHostedService<BearerRouteStartupReport>();

        return builder;
    }
}
