// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>Paths and flows that must remain reachable before tenant selection.</summary>
internal static class TenantSelectionExemptions
{
    /// <summary>Determines whether the request is served without tenant selection.</summary>
    /// <param name="context">The current request.</param>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>Whether the request is exempt.</returns>
    internal static bool IsExemptFromTenantSelection(HttpContext context, C.AuthProxy config) =>
        IsExemptPath(context, config)
        || context.HasPendingInvitation()
        || context.HasPendingRegistration();

    /// <summary>Determines whether the path is served without a tenant binding check.</summary>
    /// <param name="context">The current request.</param>
    /// <param name="config">The deployment configuration.</param>
    /// <returns>Whether the path is exempt.</returns>
    internal static bool IsExemptPath(HttpContext context, C.AuthProxy config) =>
        context.IsInvitation()
        || context.IsRegistration()
        || context.IsAuthenticationBootstrap()

        // A path the deployment declares anonymous is served without regard to who is asking, so it
        // stays reachable for a caller who happens to be signed in without having chosen a tenant.
        || context.IsAnonymousPath(config);
}
