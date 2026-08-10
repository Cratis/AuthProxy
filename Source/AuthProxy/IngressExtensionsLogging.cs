// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

internal static partial class IngressExtensionsLogging
{
    [LoggerMessage(LogLevel.Warning, "AuthProxy is running in {Mode} trusted-proxy mode with no trusted proxies configured, so it believes the X-Forwarded-For and X-Forwarded-Proto headers of every caller. Set {TrustedProxiesKey} to the addresses or CIDR ranges of the ingress in front of it, or set {ModeKey} to LoopbackOnly or TrustAny to state the choice explicitly. A future major release will refuse to start in this state.")]
    internal static partial void TrustedProxyBoundaryNotConfigured(this ILogger logger, string mode, string trustedProxiesKey, string modeKey);
}
