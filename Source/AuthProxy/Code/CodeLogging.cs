// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code;

internal static partial class CodeLogging
{
    [LoggerMessage(LogLevel.Error, "A code request cannot be sent: the code provider needs a request URL and Code:Attestation")]
    internal static partial void CodeRequestNotConfigured(this ILogger logger);

    [LoggerMessage(LogLevel.Error, "A code request could not be signed; nothing was posted")]
    internal static partial void CodeRequestCouldNotBeSigned(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "The application answered a code request with {StatusCode}")]
    internal static partial void CodeRequestRefused(this ILogger logger, int statusCode);

    [LoggerMessage(LogLevel.Error, "The code request to the application failed")]
    internal static partial void CodeRequestFailed(this ILogger logger, Exception exception);

    [LoggerMessage(LogLevel.Information, "A code request was throttled for {Scope}")]
    internal static partial void CodeRequestThrottled(this ILogger logger, string scope);

    [LoggerMessage(LogLevel.Warning, "A code sign-in was refused: {Reason}")]
    internal static partial void CodeSignInRefused(this ILogger logger, string reason);
}
