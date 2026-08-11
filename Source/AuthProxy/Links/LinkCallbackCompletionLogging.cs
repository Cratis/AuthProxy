// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

internal static partial class LinkCallbackCompletionLogging
{
    [LoggerMessage(LogLevel.Warning, "Credential link did not complete for scheme {Scheme} - the browser was answered with the generic link failure page")]
    internal static partial void LinkCallbackFailed(this ILogger logger, string scheme);
}
