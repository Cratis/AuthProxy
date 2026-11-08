// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

internal static partial class IngressExtensionsLogging
{
    [LoggerMessage(LogLevel.Warning, "AuthProxy is running in {Mode} trusted-proxy mode with no trusted proxies configured, so it is ignoring forwarded headers from every caller. The request scheme and client address remain those of the connection. Set {TrustedProxiesKey} to the addresses or CIDR ranges of the ingress in front of it, or explicitly set {ModeKey} to TrustAny when only your ingress can connect.")]
    internal static partial void TrustedProxyBoundaryNotConfigured(this ILogger logger, string mode, string trustedProxiesKey, string modeKey);

    [LoggerMessage(LogLevel.Warning, "{Variable} is set, so the host inserts its own forwarded-headers middleware ahead of every AuthProxy middleware. The peer AuthProxy records as the caller is then the one the header already replaced, and the declared trusted-proxy boundary is applied a second time to a request that has already been rewritten. Unset it and let {ModeKey} and {TrustedProxiesKey} declare the boundary.")]
    internal static partial void ForwardedHeadersEnvironmentSwitchIsOn(this ILogger logger, string variable, string modeKey, string trustedProxiesKey);

    [LoggerMessage(LogLevel.Warning, "A Data Protection key ring is configured without CredentialBinding.Resource. Deployments sharing a key ring need Cratis:AuthProxy:CredentialBinding resource and environment settings to keep credentials within their intended deployment.")]
    internal static partial void SharedKeyRingWithoutCredentialBinding(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "{Warning}")]
    internal static partial void SessionConfigurationWarning(this ILogger logger, string warning);
}
