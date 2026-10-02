// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

internal static partial class AccessTokenForwardingMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "No access token could be obtained for the signed-in user for service {Service} ({Reason}); the request is refused with 401")]
    internal static partial void AccessTokenUnavailable(this ILogger logger, string service, UserAccessTokenFailure reason);
}
