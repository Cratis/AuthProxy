// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Extension methods for registering invite services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class InvitesServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="IInviteTokenValidator"/> and the shared invitation completion.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddInvites(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IInviteTokenValidator, InviteTokenValidator>();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IInvitationAttestationIssuer, InvitationAttestationIssuer>();
        builder.Services.AddSingleton<IInvitationEntryStateProtector, InvitationEntryStateProtector>();
        builder.Services.AddSingleton<IValidateOptions<Configuration.AuthProxy>, InvitationAttestationConfigurationValidator>();
        builder.Services.AddSingleton<IInviteCompletion>(sp => new InviteCompletion(
            sp.GetRequiredService<IInviteTokenValidator>(),
            sp.GetRequiredService<IOptionsMonitor<Configuration.AuthProxy>>(),
            sp.GetRequiredService<IOptionsMonitor<Configuration.Authentication>>(),
            sp.GetRequiredService<ITenantResolver>(),
            sp.GetRequiredService<IHttpClientFactory>(),
            sp.GetRequiredService<ILogger<InviteCompletion>>(),
            sp.GetRequiredService<ICanonicalIdentityResolver>(),
            sp.GetRequiredService<IInvitationAttestationIssuer>(),
            sp.GetRequiredService<IInvitationEntryStateProtector>()));

        return builder;
    }
}
