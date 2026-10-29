// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress;

internal static partial class TrustedProxyMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "Forwarded headers were accepted from a public address because no trusted proxies are configured; set Ingress:TrustedProxies")]
    internal static partial void ForwardedHeadersFromPublicAddress(this ILogger logger);
}
