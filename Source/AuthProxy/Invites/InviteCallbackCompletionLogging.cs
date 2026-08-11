// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

internal static partial class InviteCallbackCompletionLogging
{
    [LoggerMessage(LogLevel.Information, "Invitation completed on the provider callback for scheme {Scheme}")]
    internal static partial void InvitationCompletedOnCallback(this ILogger logger, string scheme);

    [LoggerMessage(LogLevel.Warning, "Invitation exchange on the provider callback for scheme {Scheme} ended in {Result} - answering with the same outcome the post-login exchange produces")]
    internal static partial void InvitationCallbackExchangeDidNotSucceed(this ILogger logger, string scheme, InviteExchangeResult result);

    [LoggerMessage(LogLevel.Information, "Invitation capability on the provider callback for scheme {Scheme} no longer validates: {Reason} - leaving it to the post-login middleware to answer")]
    internal static partial void InvitationCallbackTokenNoLongerValidates(this ILogger logger, string scheme, InviteTokenValidationResult reason);
}
