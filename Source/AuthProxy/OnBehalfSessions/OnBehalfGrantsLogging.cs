// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

internal static partial class OnBehalfGrantsLogging
{
    [LoggerMessage(LogLevel.Error, "On-behalf grant check is not configured: OnBehalf.Service does not name a service with a backend")]
    internal static partial void GrantCheckNotConfigured(this ILogger logger);

    [LoggerMessage(LogLevel.Error, "On-behalf grant check could not be signed; nothing was sent")]
    internal static partial void GrantCheckCouldNotBeSigned(this ILogger logger);

    [LoggerMessage(LogLevel.Information, "On-behalf grant is not live (status {StatusCode})")]
    internal static partial void GrantNotLive(this ILogger logger, int statusCode);

    [LoggerMessage(LogLevel.Information, "On-behalf grant has expired")]
    internal static partial void GrantExpired(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "On-behalf grant check returned {StatusCode}")]
    internal static partial void GrantCheckUnsuccessful(this ILogger logger, int statusCode);

    [LoggerMessage(LogLevel.Warning, "On-behalf grant check answer does not follow the contract")]
    internal static partial void GrantCheckAnswerUnreadable(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "On-behalf grant check identified a different user than the one asked about")]
    internal static partial void GrantCheckNamedAnotherSubject(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "On-behalf grant check failed")]
    internal static partial void GrantCheckFailed(this ILogger logger, Exception exception);
}
