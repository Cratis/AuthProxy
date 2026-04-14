// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Extension methods for registering invite services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class InvitesServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="IInviteTokenValidator"/>.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddInvites(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IInviteTokenValidator, InviteTokenValidator>();

        return builder;
    }
}
