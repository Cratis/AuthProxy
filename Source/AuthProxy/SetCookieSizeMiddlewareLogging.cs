// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

internal static partial class SetCookieSizeMiddlewareLogging
{
    [LoggerMessage(LogLevel.Warning, "The Set-Cookie headers on the response to {Path} total {Size} bytes, above {Threshold}. A reverse proxy with a small header buffer (ingress-nginx defaults to 4k) answers 502 'upstream sent too big header'; raise its proxy-buffer-size. Cookies (header length in bytes): {Cookies}")]
    internal static partial void SetCookieHeadersLarge(this ILogger logger, string path, int size, int threshold, string cookies);
}
