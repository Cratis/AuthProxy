// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Introspection;

/// <summary>
/// Log messages of bearer-token introspection. Nothing here may take a token, its hash, the client secret or a
/// response body: they name the issuer, the outcome and the exception type, nothing else.
/// </summary>
internal static partial class BearerIntrospectionLogging
{
    [LoggerMessage(LogLevel.Warning, "Introspection of issuer '{Issuer}' could not confirm a bearer token ({Reason}).")]
    internal static partial void IntrospectionUnavailable(this ILogger logger, string issuer, string reason);

    [LoggerMessage(LogLevel.Warning, "Introspection of issuer '{Issuer}' answered with something that contradicts the validated token ({Field}). Refused.")]
    internal static partial void IntrospectionMismatch(this ILogger logger, string issuer, string field);

    [LoggerMessage(LogLevel.Error, "Introspection of issuer '{Issuer}' was refused with HTTP {Status}: AuthProxy's own client credential is probably wrong. Tokens are not confirmed until it is fixed.")]
    internal static partial void IntrospectionClientRejected(this ILogger logger, string issuer, int status);

    [LoggerMessage(LogLevel.Warning, "Introspection of issuer '{Issuer}' was unavailable on route '{Route}' of service '{Service}'. Accepted on local validation alone because the route sets IntrospectionUnavailable to Accept.")]
    internal static partial void IntrospectionUnavailableAccepted(this ILogger logger, string issuer, string route, string service);

    [LoggerMessage(LogLevel.Information, "Bearer token on route '{Route}' of service '{Service}' reported inactive by introspection. Refused.")]
    internal static partial void BearerTokenRevoked(this ILogger logger, string route, string service);

    [LoggerMessage(LogLevel.Warning, "Introspection of issuer '{Issuer}' was unavailable on route '{Route}' of service '{Service}'. Refused.")]
    internal static partial void BearerIntrospectionRefused(this ILogger logger, string issuer, string route, string service);

    [LoggerMessage(LogLevel.Warning, "Bearer route '{Route}' of service '{Service}' is an MCP route whose issuer '{Issuer}' has no Introspection configured, so a revoked token is not refused at the edge until it expires.")]
    internal static partial void BearerRouteWithoutIntrospection(this ILogger logger, string route, string service, string issuer);
}
