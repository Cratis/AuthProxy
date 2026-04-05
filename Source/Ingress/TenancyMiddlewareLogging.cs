// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress;

internal static partial class TenancyMiddlewareLogging
{
    [LoggerMessage(LogLevel.Debug, "No tenant resolved for {Path}. Redirecting to lobby")]
    internal static partial void RedirectingToLobby(this ILogger logger, string path);

    [LoggerMessage(LogLevel.Warning, "Could not resolve tenant for request {Path}. Returning 401")]
    internal static partial void CouldNotResolveTenant(this ILogger logger, string path);

    [LoggerMessage(LogLevel.Warning, "Resolved tenant '{TenantId}' does not exist for request {Path}. Returning tenant-not-found page.")]
    internal static partial void TenantDoesNotExist(this ILogger logger, Guid tenantId, string path);
}
