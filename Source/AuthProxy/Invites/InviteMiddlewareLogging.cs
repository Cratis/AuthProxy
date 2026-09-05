// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

internal static partial class InviteMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "Invite token validation failed: {Reason}")]
    internal static partial void InviteTokenValidationFailed(this ILogger logger, InviteTokenValidationResult reason);

    [LoggerMessage(LogLevel.Warning, "Invite token failed re-validation at the Phase-2 exchange forward: {Reason} - not forwarding to the exchange endpoint")]
    internal static partial void InviteExchangeTokenValidationFailed(this ILogger logger, InviteTokenValidationResult reason);

    [LoggerMessage(LogLevel.Warning, "Invite exchange rejected because the authenticated account's verified email does not match the invited email")]
    internal static partial void InviteEmailMismatch(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "Invite exchange rejected because the identity provider supplied no email address - the invitation is bound to one and cannot be evaluated")]
    internal static partial void InviteEmailUnavailable(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "Invite exchange URL is not configured - skipping invite exchange")]
    internal static partial void InviteExchangeUrlNotConfigured(this ILogger logger);

    [LoggerMessage(LogLevel.Error, "Failed to call invite exchange endpoint at {Url}")]
    internal static partial void FailedToCallInviteExchangeEndpoint(this ILogger logger, Exception exception, string url);

    [LoggerMessage(LogLevel.Warning, "Invite exchange endpoint returned {StatusCode}")]
    internal static partial void InviteExchangeEndpointFailed(this ILogger logger, int statusCode);

    [LoggerMessage(LogLevel.Information, "Invite exchanged successfully")]
    internal static partial void InviteExchangedSuccessfully(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "Invite exchange rejected because the authenticated subject is already associated with an existing user")]
    internal static partial void InviteSubjectAlreadyExists(this ILogger logger);

    [LoggerMessage(LogLevel.Information, "Invitation not completed because the authenticated session was not established by this invitation's own challenge - taking the caller through provider selection instead")]
    internal static partial void InviteSessionWasNotEstablishedByTheInvitation(this ILogger logger);

    [LoggerMessage(LogLevel.Information, "Invitation completion destination selected: {Destination} (tenant relation: {TenantRelation})")]
    internal static partial void InvitationCompletionDestinationSelected(
        this ILogger logger,
        Configuration.InvitationCompletionDestination destination,
        InvitationTenantRelation tenantRelation);
}
