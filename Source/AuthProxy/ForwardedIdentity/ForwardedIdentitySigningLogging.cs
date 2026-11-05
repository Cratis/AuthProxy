// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

internal static partial class ForwardedIdentitySigningLogging
{
    [LoggerMessage(0, LogLevel.Warning, "Forwarded identity signing refused (Refused)")]
    internal static partial void SigningRefused(this ILogger logger);
}
