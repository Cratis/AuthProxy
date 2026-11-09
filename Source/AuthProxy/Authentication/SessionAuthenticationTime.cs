// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Records and reads AuthProxy-authored authentication time, independent of cookie renewal.</summary>
internal static class SessionAuthenticationTime
{
    /// <summary>The protected cookie property paired with the reserved claim.</summary>
    internal const string PropertyKey = ".cratis.at";

    /// <summary>Replaces untrusted time claims with the completed authentication time.</summary>
    /// <param name="principal">The session principal.</param>
    /// <param name="properties">The protected session properties.</param>
    /// <param name="time">The authentication time.</param>
    internal static void Stamp(ClaimsPrincipal principal, AuthenticationProperties properties, DateTimeOffset time)
    {
        foreach (var identity in principal.Identities)
        {
            foreach (var claim in identity.Claims.Where(_ => IsTime(_.Type)).ToArray())
            {
                identity.TryRemoveClaim(claim);
            }
        }
        var value = time.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        principal.Identities.First().AddClaim(new Claim(SessionClaims.AuthenticationTime, value));
        properties.Items[PropertyKey] = value;
    }

    /// <summary>Checks the matching time pair against a deterministic clock and age limit.</summary>
    /// <param name="principal">The session principal.</param>
    /// <param name="properties">The protected session properties.</param>
    /// <param name="maxAge">The maximum allowed age.</param>
    /// <param name="now">The current time.</param>
    /// <returns>Whether the session carries a trusted, recent time.</returns>
    internal static bool IsFresh(ClaimsPrincipal principal, AuthenticationProperties? properties, TimeSpan maxAge, DateTimeOffset now) =>
        TryRead(principal, properties, out var time) && time <= now && now - time <= maxAge;

    /// <summary>Reads exactly one time claim matching its protected cookie marker.</summary>
    /// <param name="principal">The session principal.</param>
    /// <param name="properties">The protected session properties.</param>
    /// <param name="time">The recorded authentication time.</param>
    /// <returns>Whether a matching, well-formed time pair exists.</returns>
    internal static bool TryRead(ClaimsPrincipal principal, AuthenticationProperties? properties, out DateTimeOffset time)
    {
        time = default;
        var claims = principal.Claims.Where(_ => IsTime(_.Type)).ToArray();
        return claims.Length == 1
            && claims[0].Type == SessionClaims.AuthenticationTime
            && properties?.Items.TryGetValue(PropertyKey, out var marker) == true
            && string.Equals(marker, claims[0].Value, StringComparison.Ordinal)
            && TryParse(claims[0].Value, out time);
    }

    /// <summary>Parses a nonnegative Unix timestamp within the supported date range.</summary>
    /// <param name="value">The timestamp text.</param>
    /// <param name="time">The parsed time.</param>
    /// <returns>Whether the value represents a supported Unix timestamp.</returns>
    internal static bool TryParse(string? value, out DateTimeOffset time)
    {
        time = default;
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) || seconds < 0 || seconds > 253402300799)
        {
            return false;
        }
        time = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return true;
    }

    static bool IsTime(string type) => type.StartsWith(SessionClaims.AuthenticationTime, StringComparison.OrdinalIgnoreCase);
}
