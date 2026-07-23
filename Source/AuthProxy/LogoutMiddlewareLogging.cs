// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

internal static partial class LogoutMiddlewareLogging
{
    [LoggerMessage(LogLevel.Debug, "Redirecting to the end-session endpoint for provider {Scheme} to complete RP-initiated logout")]
    internal static partial void RedirectingToEndSession(this ILogger logger, string scheme);

    [LoggerMessage(LogLevel.Debug, "Performing a local-only logout for provider {Scheme} (no end-session endpoint available)")]
    internal static partial void LocalLogoutOnly(this ILogger logger, string scheme);
}
