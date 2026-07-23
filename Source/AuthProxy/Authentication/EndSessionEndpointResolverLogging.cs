// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

internal static partial class EndSessionEndpointResolverLogging
{
    [LoggerMessage(LogLevel.Warning, "Could not resolve the end-session endpoint for scheme {Scheme}; falling back to a local-only logout")]
    internal static partial void EndSessionDiscoveryFailed(this ILogger logger, string scheme, Exception exception);
}
