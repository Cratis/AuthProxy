// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

internal static partial class UserAccessTokensLogging
{
    [LoggerMessage(LogLevel.Warning, "The OIDC provider {Scheme} a session signed in with is no longer configured; no access token can be obtained for it")]
    internal static partial void ProviderNoLongerConfigured(this ILogger logger, string scheme);

    [LoggerMessage(LogLevel.Warning, "OIDC provider {Scheme} refused to refresh an access token with status {StatusCode} and error {Error}")]
    internal static partial void RefreshRefused(this ILogger logger, string scheme, int statusCode, string error);

    [LoggerMessage(LogLevel.Warning, "OIDC provider {Scheme} answered a token refresh without a bearer access token")]
    internal static partial void RefreshAnsweredWithoutBearerToken(this ILogger logger, string scheme);

    [LoggerMessage(LogLevel.Warning, "Refreshing an access token at OIDC provider {Scheme} failed")]
    internal static partial void RefreshFailed(this ILogger logger, string scheme, Exception exception);
}
