// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Holds the log messages for <see cref="ClientCredentialsServiceResolver"/>.
/// </summary>
internal static partial class ClientCredentialsServiceResolverLogging
{
    /// <summary>
    /// Logs that no services are configured for client credentials.
    /// </summary>
    /// <param name="logger">The logger to write to.</param>
    [LoggerMessage(LogLevel.Warning, "A client-credentials token was requested but no services are configured for client credentials.")]
    internal static partial void NoServicesConfiguredForClientCredentials(this ILogger<ClientCredentialsServiceResolver> logger);

    /// <summary>
    /// Logs that the requested service is not configured for client credentials.
    /// </summary>
    /// <param name="logger">The logger to write to.</param>
    /// <param name="serviceName">The requested service name.</param>
    [LoggerMessage(LogLevel.Warning, "A client-credentials token was requested for service '{ServiceName}', which is not configured for client credentials.")]
    internal static partial void RequestedServiceNotConfiguredForClientCredentials(this ILogger<ClientCredentialsServiceResolver> logger, string serviceName);
}
