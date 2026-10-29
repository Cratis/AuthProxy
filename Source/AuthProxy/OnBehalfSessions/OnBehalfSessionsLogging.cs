// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

internal static partial class OnBehalfSessionsLogging
{
    [LoggerMessage(LogLevel.Warning, "On-behalf session refused: the actor does not satisfy the actor requirements (unsatisfied claim '{Claim}')")]
    internal static partial void ActorNotPermitted(this ILogger logger, string claim);

    [LoggerMessage(LogLevel.Warning, "On-behalf session refused: the application did not acknowledge the start")]
    internal static partial void SessionStartNotAcknowledged(this ILogger logger);

    [LoggerMessage(LogLevel.Information, "On-behalf session {SessionId} started")]
    internal static partial void SessionStarted(this ILogger logger, string sessionId);

    [LoggerMessage(LogLevel.Information, "On-behalf session {SessionId} ended: {Reason}")]
    internal static partial void SessionEnded(this ILogger logger, string sessionId, string reason);

    [LoggerMessage(LogLevel.Error, "On-behalf assertion could not be signed; the request was refused")]
    internal static partial void AssertionCouldNotBeSigned(this ILogger logger);
}
