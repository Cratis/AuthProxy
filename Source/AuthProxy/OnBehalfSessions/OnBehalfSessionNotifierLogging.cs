// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

internal static partial class OnBehalfSessionNotifierLogging
{
    [LoggerMessage(LogLevel.Error, "On-behalf session notification {Path} is not configured: OnBehalf.Service does not name a service with a backend")]
    internal static partial void SessionNotificationNotConfigured(this ILogger logger, string path);

    [LoggerMessage(LogLevel.Error, "On-behalf session notification {Path} could not be signed; nothing was posted")]
    internal static partial void SessionNotificationCouldNotBeSigned(this ILogger logger, string path);

    [LoggerMessage(LogLevel.Warning, "On-behalf session notification {Path} returned {StatusCode}")]
    internal static partial void SessionNotificationUnsuccessful(this ILogger logger, string path, int statusCode);

    [LoggerMessage(LogLevel.Warning, "On-behalf session notification {Path} failed")]
    internal static partial void SessionNotificationFailed(this ILogger logger, Exception exception, string path);

    [LoggerMessage(LogLevel.Information, "On-behalf session notification {Path} acknowledged")]
    internal static partial void SessionNotified(this ILogger logger, string path);
}
