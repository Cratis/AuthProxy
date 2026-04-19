// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

internal static partial class IdentityDetailsResolverLogging
{
    [LoggerMessage(LogLevel.Debug, "Identity details resolved and stored in cookie for user {UserId}")]
    internal static partial void IdentityDetailsCookieWritten(this ILogger logger, string userId);

    [LoggerMessage(LogLevel.Debug, "Identity details served from cache for user {UserId}")]
    internal static partial void IdentityDetailsCacheHit(this ILogger logger, string userId);

    [LoggerMessage(LogLevel.Debug, "Calling identity endpoint {Url} for service '{Service}'")]
    internal static partial void CallingIdentityEndpoint(this ILogger logger, string url, string service);

    [LoggerMessage(LogLevel.Debug, "Calling identity endpoint for service '{Service}' with UserId={UserId}")]
    internal static partial void CallingIdentityEndpointWithPrincipal(this ILogger logger, string service, string userId);

    [LoggerMessage(LogLevel.Error, "Error calling identity endpoint for service '{Service}'")]
    internal static partial void ErrorCallingIdentityEndpoint(this ILogger logger, Exception exception, string service);

    [LoggerMessage(LogLevel.Warning, "Service '{Service}' returned 403 for user {UserId} - access denied")]
    internal static partial void IdentityEndpointForbidden(this ILogger logger, string service, string userId);

    [LoggerMessage(LogLevel.Warning, "Identity endpoint for '{Service}' returned {StatusCode}. Identity details skipped. Response body: {Body}")]
    internal static partial void IdentityEndpointUnsuccessful(this ILogger logger, string service, int statusCode, string body);

    [LoggerMessage(LogLevel.Warning, "Could not parse identity response from '{Service}'")]
    internal static partial void CouldNotParseIdentityResponse(this ILogger logger, Exception exception, string service);
}
