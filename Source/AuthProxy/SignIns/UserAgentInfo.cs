// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Represents the browser and operating system parsed from a request's <c language="text">User-Agent</c> header.
/// </summary>
/// <param name="Browser">The browser name (for example <c language="text">Chrome</c>, <c language="text">Safari</c>, <c language="text">Firefox</c>), or an empty string when unknown.</param>
/// <param name="OperatingSystem">The operating system name (for example <c language="text">Windows</c>, <c language="text">macOS</c>, <c language="text">iOS</c>), or an empty string when unknown.</param>
/// <param name="Raw">The raw <c language="text">User-Agent</c> header value.</param>
public record UserAgentInfo(string Browser, string OperatingSystem, string Raw)
{
    /// <summary>
    /// Represents an unknown <see cref="UserAgentInfo"/> with no browser, operating system, or raw value.
    /// </summary>
    public static readonly UserAgentInfo Unknown = new(string.Empty, string.Empty, string.Empty);
}
