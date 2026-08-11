// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

internal static partial class RemoteAuthenticationFailureHandlerLogging
{
    [LoggerMessage(LogLevel.Warning, "Remote sign-in through scheme {Scheme} failed: {Reason}. Redirecting to provider selection")]
    internal static partial void RemoteSignInFailed(this ILogger logger, string scheme, string reason);

    [LoggerMessage(LogLevel.Information, "Remote sign-in through scheme {Scheme} was denied by the identity provider. Redirecting to provider selection")]
    internal static partial void RemoteSignInAccessDenied(this ILogger logger, string scheme);

    [LoggerMessage(LogLevel.Warning, "Credential-link challenge through scheme {Scheme} failed. Ending the link flow on the failure page")]
    internal static partial void LinkChallengeFailed(this ILogger logger, string scheme);
}
