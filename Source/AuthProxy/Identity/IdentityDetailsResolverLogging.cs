// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

internal static partial class IdentityDetailsResolverLogging
{
    [LoggerMessage(LogLevel.Debug, "Identity details resolved and stored in cookie for user {UserId}")]
    internal static partial void IdentityDetailsCookieWritten(this ILogger logger, string userId);

    [LoggerMessage(LogLevel.Debug, "Calling identity endpoint {Url} for microservice '{Microservice}'")]
    internal static partial void CallingIdentityEndpoint(this ILogger logger, string url, string microservice);

    [LoggerMessage(LogLevel.Error, "Error calling identity endpoint for microservice '{Microservice}'")]
    internal static partial void ErrorCallingIdentityEndpoint(this ILogger logger, Exception exception, string microservice);

    [LoggerMessage(LogLevel.Warning, "Microservice '{Microservice}' returned 403 for user {UserId} - access denied")]
    internal static partial void IdentityEndpointForbidden(this ILogger logger, string microservice, string userId);

    [LoggerMessage(LogLevel.Warning, "Identity endpoint for '{Microservice}' returned {StatusCode}. Identity details skipped")]
    internal static partial void IdentityEndpointUnsuccessful(this ILogger logger, string microservice, int statusCode);

    [LoggerMessage(LogLevel.Warning, "Could not parse identity response from '{Microservice}'")]
    internal static partial void CouldNotParseIdentityResponse(this ILogger logger, Exception exception, string microservice);
}
