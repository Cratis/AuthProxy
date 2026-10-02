// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

internal static partial class OidcClientAssertionsLogging
{
    [LoggerMessage(LogLevel.Error, "The {Source} client credential of OIDC provider {Provider} is unavailable; the provider's token requests will fail")]
    internal static partial void ClientCredentialUnavailable(this ILogger logger, string provider, string source, Exception exception);

    [LoggerMessage(LogLevel.Warning, "The client certificate of OIDC provider {Provider} has expired; loading it again")]
    internal static partial void ClientCertificateExpired(this ILogger logger, string provider);
}
