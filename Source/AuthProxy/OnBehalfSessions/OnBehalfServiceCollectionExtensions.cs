// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Extension methods for registering on-behalf session services.
/// </summary>
public static class OnBehalfServiceCollectionExtensions
{
    /// <summary>
    /// Registers the services behind on-behalf sessions. Registering them changes nothing for a deployment that does
    /// not configure the <c language="text">OnBehalf</c> section.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddActingOnBehalf(this WebApplicationBuilder builder)
    {
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IValidateOptions<Configuration.AuthProxy>, OnBehalfConfigurationValidator>();
        builder.Services.AddSingleton<IOnBehalfSessionProtector, OnBehalfSessionProtector>();
        builder.Services.AddSingleton<OnBehalfSessionCookie>();
        builder.Services.AddSingleton<OnBehalfSessionLedger>();
        builder.Services.AddSingleton<IOnBehalfAttestations, OnBehalfAttestations>();
        builder.Services.AddSingleton<IOnBehalfGrants, OnBehalfGrants>();
        builder.Services.AddSingleton<IOnBehalfSessionNotifier, OnBehalfSessionNotifier>();
        builder.Services.AddSingleton<IOnBehalfSessions, OnBehalfSessions>();
        return builder;
    }
}
