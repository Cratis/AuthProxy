// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Extension methods for registering sign-in notification services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class SignInsServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="ISignInNotifier"/> and its <see cref="IClientLocationResolver"/> used to
    /// notify the application of completed sign-ins.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddSignIns(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IClientLocationResolver, ClientLocationResolver>();
        builder.Services.AddSingleton<ISignInNotifier, SignInNotifier>();

        return builder;
    }
}
