// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BackendHops;

/// <summary>
/// Registers shared backend transport validation and live material.
/// </summary>
internal static class BackendTlsServiceCollectionExtensions
{
    /// <summary>
    /// Adds the backend TLS policy and polling service.
    /// </summary>
    /// <param name="services">The application services.</param>
    internal static void AddBackendTls(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IBackendTlsMaterialSource, BackendTlsMaterialSource>();
        services.TryAddSingleton<BackendTlsHttpClientPolicy>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<C.AuthProxy>, BackendTlsConfigurationValidator>());
        services.AddOptions<C.AuthProxy>().ValidateOnStart();
        services.AddHostedService<BackendHopTransportStartupReport>();
        services.AddHostedService<BackendTlsReloader>();
    }
}
