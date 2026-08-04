// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Parses a <c>User-Agent</c> header into a coarse browser and operating-system description.
/// </summary>
/// <remarks>
/// This is a deliberately lightweight, dependency-free heuristic — it recognizes the mainstream browsers and
/// operating systems well enough to tell a user "you signed in from Chrome on Windows", without pulling in a
/// full user-agent database. It is not intended to be exhaustive; anything it does not recognize is reported
/// as an empty string rather than guessed.
/// </remarks>
public static class UserAgentParser
{
    /// <summary>
    /// Parses the supplied <c>User-Agent</c> header value.
    /// </summary>
    /// <param name="userAgent">The raw <c>User-Agent</c> header value.</param>
    /// <returns>The parsed <see cref="UserAgentInfo"/>; <see cref="UserAgentInfo.Unknown"/> when the value is empty.</returns>
    public static UserAgentInfo Parse(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return UserAgentInfo.Unknown;
        }

        return new UserAgentInfo(ResolveBrowser(userAgent), ResolveOperatingSystem(userAgent), userAgent);
    }

    static string ResolveBrowser(string userAgent)
    {
        // Order matters: several browsers embed the tokens of the browsers they are derived from. Edge and
        // Opera carry "Chrome"; Chrome carries "Safari"; so the most specific token has to be checked first.
        if (Contains(userAgent, "Edg"))
        {
            return "Edge";
        }

        if (Contains(userAgent, "OPR") || Contains(userAgent, "Opera"))
        {
            return "Opera";
        }

        if (Contains(userAgent, "SamsungBrowser"))
        {
            return "Samsung Internet";
        }

        if (Contains(userAgent, "Firefox") || Contains(userAgent, "FxiOS"))
        {
            return "Firefox";
        }

        if (Contains(userAgent, "Chrome") || Contains(userAgent, "CriOS"))
        {
            return "Chrome";
        }

        if (Contains(userAgent, "Safari"))
        {
            return "Safari";
        }

        return string.Empty;
    }

    static string ResolveOperatingSystem(string userAgent)
    {
        // iOS and iPadOS have to be recognized before macOS: an iPad's user-agent contains "Mac OS X".
        if (Contains(userAgent, "iPhone") || Contains(userAgent, "iPad") || Contains(userAgent, "iPod"))
        {
            return "iOS";
        }

        if (Contains(userAgent, "Android"))
        {
            return "Android";
        }

        if (Contains(userAgent, "Windows"))
        {
            return "Windows";
        }

        if (Contains(userAgent, "Mac OS X") || Contains(userAgent, "Macintosh"))
        {
            return "macOS";
        }

        if (Contains(userAgent, "CrOS"))
        {
            return "ChromeOS";
        }

        if (Contains(userAgent, "Linux"))
        {
            return "Linux";
        }

        return string.Empty;
    }

    static bool Contains(string value, string token) => value.Contains(token, StringComparison.OrdinalIgnoreCase);
}
