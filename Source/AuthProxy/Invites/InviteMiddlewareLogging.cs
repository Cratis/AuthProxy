// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

internal static partial class InviteMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "Invite token validation failed for path {Path}")]
    internal static partial void InviteTokenValidationFailed(this ILogger logger, string path);

    [LoggerMessage(LogLevel.Warning, "Invite exchange URL is not configured - skipping invite exchange")]
    internal static partial void InviteExchangeUrlNotConfigured(this ILogger logger);

    [LoggerMessage(LogLevel.Error, "Failed to call invite exchange endpoint at {Url}")]
    internal static partial void FailedToCallInviteExchangeEndpoint(this ILogger logger, Exception exception, string url);

    [LoggerMessage(LogLevel.Warning, "Invite exchange endpoint returned {StatusCode} for subject {Subject}")]
    internal static partial void InviteExchangeEndpointFailed(this ILogger logger, int statusCode, string subject);

    [LoggerMessage(LogLevel.Information, "Invite exchanged successfully for subject {Subject}")]
    internal static partial void InviteExchangedSuccessfully(this ILogger logger, string subject);

    [LoggerMessage(LogLevel.Warning, "Invite exchange rejected because subject {Subject} is already associated with an existing user")]
    internal static partial void InviteSubjectAlreadyExists(this ILogger logger, string subject);
}
