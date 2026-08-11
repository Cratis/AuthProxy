// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

internal static partial class IdentityForwardingGuardMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "Authenticated session could not be turned into a forwardable identity for route {Route}. Terminating the session instead of proxying without identity headers")]
    internal static partial void TerminatingUnforwardableSession(this ILogger logger, string route);
}
