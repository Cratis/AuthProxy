// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

internal static partial class LinkMiddlewareLogging
{
    [LoggerMessage(LogLevel.Debug, "Initiating credential link challenge for scheme {Scheme}")]
    internal static partial void InitiatingLink(this ILogger logger, string scheme);

    [LoggerMessage(LogLevel.Warning, "Credential link requested for provider {Scheme} which is not configured")]
    internal static partial void LinkProviderNotConfigured(this ILogger logger, string scheme);
}
