// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Extension methods for adding <see cref="InviteMiddleware"/> to the request pipeline.
/// </summary>
internal static class InviteApplicationBuilderExtensions
{
    /// <summary>
    /// Adds <see cref="InviteMiddleware"/>, constructed with the registered <see cref="InvitationLifecycle"/>.
    /// </summary>
    /// <param name="app">The <see cref="IApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="IApplicationBuilder"/> for chaining.</returns>
    internal static IApplicationBuilder UseInviteMiddleware(this IApplicationBuilder app) =>

        // Passing the collaborator explicitly selects the constructor that receives it, while a no-argument
        // UseMiddleware<InviteMiddleware>() elsewhere keeps choosing the released constructors. The lifecycle is
        // resolved when the pipeline is built, as UseMiddleware does, so UseIngress without AddInvites still composes.
        app.Use(next => ActivatorUtilities.CreateInstance<InviteMiddleware>(
            app.ApplicationServices,
            next,
            app.ApplicationServices.GetRequiredService<InvitationLifecycle>()).InvokeAsync);
}
