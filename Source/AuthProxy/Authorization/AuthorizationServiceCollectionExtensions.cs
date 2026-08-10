// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>
/// Extension methods for registering the first-gate authorization services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class AuthorizationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the access policy and the validation that refuses an unsatisfiable claim requirement at startup.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddIngressAuthorization(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IAccessPolicy, AccessPolicy>();
        builder.Services.AddSingleton<IValidateOptions<C.AuthProxy>, AuthorizationConfigurationValidator>();

        return builder;
    }
}
