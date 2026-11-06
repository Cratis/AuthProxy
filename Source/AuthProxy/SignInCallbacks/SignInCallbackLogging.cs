// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks;

internal static partial class SignInCallbackLogging
{
    [LoggerMessage(LogLevel.Warning, "The sign-in callback {Kind} for service {Service} requires HTTPS while forwarded-identity signing is configured")]
    internal static partial void SignInCallbackRequiresHttps(this ILogger logger, SignInCallbackKind kind, string service);

    [LoggerMessage(LogLevel.Warning, "The sign-in callback {Kind} for service {Service} could not be signed and was not sent")]
    internal static partial void SignInCallbackCouldNotBeSigned(this ILogger logger, SignInCallbackKind kind, string service);

    [LoggerMessage(LogLevel.Debug, "Sign-in callback {Kind} delivered to service {Service}")]
    internal static partial void CallbackDelivered(this ILogger logger, string service, SignInCallbackKind kind);

    [LoggerMessage(LogLevel.Warning, "Service {Service} refused the sign-in callback {Kind} with status {StatusCode}")]
    internal static partial void CallbackRefused(this ILogger logger, string service, SignInCallbackKind kind, int statusCode);

    [LoggerMessage(LogLevel.Warning, "Service {Service} did not answer the sign-in callback {Kind} within {Timeout}")]
    internal static partial void CallbackTimedOut(this ILogger logger, string service, SignInCallbackKind kind, TimeSpan timeout);

    [LoggerMessage(LogLevel.Warning, "The sign-in callback {Kind} could not be delivered to service {Service}")]
    internal static partial void CallbackFailed(this ILogger logger, Exception exception, string service, SignInCallbackKind kind);

    [LoggerMessage(LogLevel.Warning, "The sign-in callback {Kind} for service {Service} was dropped because the delivery queue is full")]
    internal static partial void CallbackDropped(this ILogger logger, string service, SignInCallbackKind kind);

    [LoggerMessage(LogLevel.Warning, "A sign-in callback {Kind} for service {Service} could not be prepared and was skipped")]
    internal static partial void CallbackNotPrepared(this ILogger logger, Exception exception, string service, SignInCallbackKind kind);

    [LoggerMessage(LogLevel.Debug, "Sign-in callback {Kind} for service {Service} was skipped because the user's identity did not resolve")]
    internal static partial void CallbackWithoutIdentity(this ILogger logger, string service, SignInCallbackKind kind);
}
