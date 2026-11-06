// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Extension methods for registering the sign-in callbacks.
/// </summary>
public static class SignInCallbacksServiceCollectionExtensions
{
    /// <summary>
    /// Registers the sign-in callbacks: the decision of when a service is told about a user, the background delivery
    /// and the configuration check. Calling it more than once registers each of them once.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddSignInCallbacks(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IForwardedIdentitySigner, ForwardedIdentitySigner>();
        services.TryAddSingleton<ISignInCallbackQueue, SignInCallbackQueue>();
        services.TryAddSingleton<ISignInCallbackSender, SignInCallbackSender>();
        services.TryAddSingleton<ISignInCallbackDispatcher, SignInCallbackDispatcher>();
        services.AddHttpClient();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, SignInCallbackDelivery>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<Configuration.AuthProxy>, SignInCallbackConfigurationValidator>());
        return services;
    }
}
