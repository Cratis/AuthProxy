// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

internal static partial class LinkSubjectExchangerLogging
{
    [LoggerMessage(LogLevel.Warning, "Link exchange URL is not configured - skipping link exchange")]
    internal static partial void LinkExchangeUrlNotConfigured(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "Link exchange is missing the one-time link token - skipping link exchange")]
    internal static partial void LinkTokenMissing(this ILogger logger);

    [LoggerMessage(LogLevel.Warning, "Link exchange could not resolve a subject from the authenticated identity")]
    internal static partial void LinkSubjectMissing(this ILogger logger);

    [LoggerMessage(LogLevel.Error, "Failed to call link exchange endpoint at {Url}")]
    internal static partial void FailedToCallLinkExchangeEndpoint(this ILogger logger, Exception exception, string url);

    [LoggerMessage(LogLevel.Warning, "Link exchange endpoint returned {StatusCode}")]
    internal static partial void LinkExchangeEndpointFailed(this ILogger logger, int statusCode);

    [LoggerMessage(LogLevel.Information, "Link exchanged successfully")]
    internal static partial void LinkExchangedSuccessfully(this ILogger logger);
}
