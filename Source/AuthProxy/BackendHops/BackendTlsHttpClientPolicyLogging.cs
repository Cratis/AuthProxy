// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops;

internal static partial class BackendTlsHttpClientPolicyLogging
{
    [LoggerMessage(0, LogLevel.Warning, "Backend TLS handshake refused for {Host}: {Reason}")]
    internal static partial void HandshakeRefused(this ILogger<BackendTlsHttpClientPolicy> logger, string host, string reason);
}
