// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

internal static partial class InvitationTokenKeysLogging
{
    [LoggerMessage(LogLevel.Warning, "Invitation-token metadata unavailable at {Url}.")]
    internal static partial void InvitationMetadataUnavailable(this ILogger logger, Exception exception, string url);

    [LoggerMessage(LogLevel.Warning, "Invitation-token metadata rejected at {Url}: {Reason}")]
    internal static partial void InvitationMetadataRejected(this ILogger logger, string url, string reason);

    [LoggerMessage(LogLevel.Warning, "Invitation-token key set at {Url} has no usable keys.")]
    internal static partial void InvitationKeySetEmpty(this ILogger logger, string url);

    [LoggerMessage(LogLevel.Warning, "Invitation-token keys at {Url} are stale; failing closed.")]
    internal static partial void InvitationKeysStale(this ILogger logger, string url);
}
