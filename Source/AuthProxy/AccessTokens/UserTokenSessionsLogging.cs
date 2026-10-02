// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

internal static partial class UserTokenSessionsLogging
{
    [LoggerMessage(LogLevel.Warning, "OIDC provider {Scheme} issued no refresh token at sign-in, so services that forward user access tokens will refuse this session. Request the offline_access scope from the provider")]
    internal static partial void NoRefreshTokenIssued(this ILogger logger, string scheme);
}
