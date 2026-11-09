// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

internal static partial class VerifiedUpstreamClaimsLogging
{
    [LoggerMessage(LogLevel.Warning, "The token endpoint response carried no access token, so no verified claims are sent for this sign-in")]
    internal static partial void AccessTokenAbsent(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "The upstream access token was refused ({Reason}), so no verified claims are sent for this sign-in")]
    internal static partial void AccessTokenRefused(this ILogger logger, string reason);

    [LoggerMessage(LogLevel.Warning, "The upstream access token and identity token name different subjects, so no verified claims are sent for this sign-in")]
    internal static partial void SubjectMismatch(this ILogger logger);
}
