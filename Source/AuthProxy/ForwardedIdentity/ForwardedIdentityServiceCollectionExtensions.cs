// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// Extension methods for registering signed forwarding.
/// </summary>
public static class ForwardedIdentityServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="IForwardedIdentitySigner"/> and its configuration validator, once.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same service collection for chaining.</returns>
    /// <remarks>
    /// Every registration that sends a request to a service on a caller's behalf calls this, so the signer is present
    /// in any composition that can forward identity, however it was assembled.
    /// </remarks>
    public static IServiceCollection AddForwardedIdentitySigning(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IForwardedIdentitySigner, ForwardedIdentitySigner>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<C.AuthProxy>, ForwardingAttestationConfigurationValidator>());

        return services;
    }
}
