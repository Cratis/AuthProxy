// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization;

internal static partial class AccessControlMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "Authenticated caller does not satisfy the required claim '{Claim}' for request {Path}. Serving the not-authorized page.")]
    internal static partial void AccessDenied(this ILogger logger, string claim, string path);
}
