// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Extension methods for registering identity services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class IdentityServiceCollectionExtensions
{
    /// <summary>
    /// Registers the HTTP client factory and the <see cref="IIdentityDetailsResolver"/>.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddIdentityResolution(this WebApplicationBuilder builder)
    {
        builder.Services.AddHttpClient();
        builder.Services.AddSingleton<IIdentityDetailsPrincipalEnricher, InviteTokenInvitationIdPrincipalEnricher>();
        builder.Services.AddSingleton<IIdentityDetailsPrincipalEnricher, InviteTokenClaimsPrincipalEnricher>();
        builder.Services.AddSingleton<IIdentityDetailsResolver, IdentityDetailsResolver>();

        return builder;
    }
}
