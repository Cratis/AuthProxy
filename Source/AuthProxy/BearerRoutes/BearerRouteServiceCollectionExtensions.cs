// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Introspection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
    /// The maximum buffered size of an issuer metadata document or JWKS, in bytes.
    /// </summary>
    public static readonly int MaximumMetadataSize = 64 * 1024;

    /// <summary>
    /// The maximum buffered size of an introspection response, in bytes.
    /// </summary>
    public static readonly int MaximumIntrospectionResponseSize = 16 * 1024;

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
        builder.Services.AddHttpClient(BearerRouteDefaults.MetadataHttpClientName, client =>
        {
            client.Timeout = MetadataTimeout;
            client.MaxResponseContentBufferSize = MaximumMetadataSize;
        })

            // An issuer's response cannot choose a second address for AuthProxy to fetch.
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });

        // The deadline of an introspection call is the issuer's configured Timeout, enforced by the call itself.
        builder.Services.AddHttpClient(BearerRouteDefaults.IntrospectionHttpClientName, client =>
        {
            client.Timeout = Timeout.InfiniteTimeSpan;
            client.MaxResponseContentBufferSize = MaximumIntrospectionResponseSize;
        })

            // The endpoint cannot redirect AuthProxy, and the token is never replayed anywhere else.
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IntrospectionCache>();
        builder.Services.AddSingleton<IBearerTokenIntrospector, BearerTokenIntrospector>();
        builder.Services.AddSingleton<IBearerIssuerMetadata, BearerIssuerMetadata>();
        builder.Services.AddSingleton<IBearerTokenValidator, BearerTokenValidator>();
        builder.Services.AddSingleton<IBearerRouteForwarder, BearerRouteForwarder>();
        builder.Services.AddSingleton<IValidateOptions<C.AuthProxy>, BearerRouteConfigurationValidator>();
        builder.Services.AddHostedService<BearerRouteStartupReport>();

        return builder;
    }
}
