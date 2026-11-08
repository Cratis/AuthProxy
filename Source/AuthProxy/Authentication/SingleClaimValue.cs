// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Reads a single, exact claim type without accepting repeated values.</summary>
static class SingleClaimValue
{
    /// <summary>Reads one nonempty claim value.</summary>
    /// <param name="claims">The claims to inspect.</param>
    /// <param name="claimType">The exact claim type.</param>
    /// <param name="value">The value found.</param>
    /// <param name="trim">Whether to trim the value.</param>
    /// <returns>Whether exactly one nonempty value was found.</returns>
    internal static bool TryGetSingleValue(IEnumerable<Claim> claims, string claimType, out string value, bool trim = true)
    {
        var values = claims.Where(_ => string.Equals(_.Type, claimType, StringComparison.Ordinal)).Take(2).ToArray();
        value = values.Length == 1 ? values[0].Value : string.Empty;
        if (trim) value = value.Trim();
        return value.Length > 0;
    }
}
