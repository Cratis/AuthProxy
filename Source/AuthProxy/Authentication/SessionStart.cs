// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Records the completed sign-in time in protected ticket properties, independent of cookie renewal.</summary>
internal static class SessionStart
{
    /// <summary>The protected cookie property holding the original session start.</summary>
    internal const string PropertyKey = ".cratis.ss";

    /// <summary>Replaces an incoming property with AuthProxy's completed sign-in time.</summary>
    /// <param name="properties">The protected session properties.</param>
    /// <param name="time">The sign-in time.</param>
    internal static void Stamp(AuthenticationProperties properties, DateTimeOffset time) =>
        properties.Items[PropertyKey] = time.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

    /// <summary>Reads a valid session start without inventing one for legacy tickets.</summary>
    /// <param name="properties">The protected session properties.</param>
    /// <param name="time">The original sign-in time.</param>
    /// <returns>Whether the ticket carries a supported nonnegative Unix timestamp.</returns>
    internal static bool TryRead(AuthenticationProperties? properties, out DateTimeOffset time)
    {
        time = default;
        return properties?.Items.TryGetValue(PropertyKey, out var value) == true
            && SessionAuthenticationTime.TryParse(value, out time);
    }
}
