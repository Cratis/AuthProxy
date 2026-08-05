// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

internal static partial class IdentityAuthorizationCacheLogging
{
    [LoggerMessage(LogLevel.Debug, "A recorded identity authorization could not be unsealed and was ignored. The caller will be re-authorized against the configured services.")]
    internal static partial void IdentityAuthorizationRecordRejected(this ILogger logger);
}
