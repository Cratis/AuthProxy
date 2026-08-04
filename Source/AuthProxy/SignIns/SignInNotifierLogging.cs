// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

internal static partial class SignInNotifierLogging
{
    [LoggerMessage(LogLevel.Warning, "Sign-in notification could not resolve a subject from the authenticated identity")]
    internal static partial void SignInSubjectMissing(this ILogger logger);

    [LoggerMessage(LogLevel.Error, "Failed to call sign-in notification endpoint at {Url}")]
    internal static partial void FailedToCallSignInNotifyEndpoint(this ILogger logger, Exception exception, string url);

    [LoggerMessage(LogLevel.Warning, "Sign-in notification endpoint returned {StatusCode}")]
    internal static partial void SignInNotifyEndpointFailed(this ILogger logger, int statusCode);

    [LoggerMessage(LogLevel.Information, "Sign-in notified for subject {Subject}")]
    internal static partial void SignInNotified(this ILogger logger, string subject);
}
