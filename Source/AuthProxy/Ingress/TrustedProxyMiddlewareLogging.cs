// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress;

internal static partial class TrustedProxyMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "Forwarded headers were received but ignored because no trusted proxies are configured; set Cratis:AuthProxy:Ingress:TrustedProxies or explicitly select Cratis:AuthProxy:Ingress:Mode=TrustAny")]
    internal static partial void ForwardedHeadersIgnored(this ILogger logger);
}
