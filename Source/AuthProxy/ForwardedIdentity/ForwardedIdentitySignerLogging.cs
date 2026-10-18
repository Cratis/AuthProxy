// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

internal static partial class ForwardedIdentitySignerLogging
{
    [LoggerMessage(LogLevel.Warning, "Could not sign the forwarded identity ({Reason}); the request is not sent")]
    internal static partial void ForwardedIdentityNotSigned(this ILogger logger, string reason);

    [LoggerMessage(LogLevel.Error, "Could not sign the forwarded identity with key {KeyId}; the request is not sent")]
    internal static partial void ForwardedIdentitySigningFailed(this ILogger logger, Exception exception, string keyId);
}
