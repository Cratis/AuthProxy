// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Recognizes claim types that grant a role, so a bearer token can never carry one to a backend.
/// </summary>
/// <remarks>
/// ClaimsPrincipal.IsInRole compares claim types case-insensitively, so this does too.
/// </remarks>
static class RoleClaims
{
    /// <summary>
    /// Determines whether a claim type grants a role.
    /// </summary>
    /// <param name="claimType">The claim type.</param>
    /// <returns>True when the claim type is a role claim in any casing.</returns>
    internal static bool Is(string claimType) =>
        string.Equals(claimType, ClaimTypes.Role, StringComparison.OrdinalIgnoreCase)
        || string.Equals(claimType, "role", StringComparison.OrdinalIgnoreCase)
        || string.Equals(claimType, "roles", StringComparison.OrdinalIgnoreCase);
}
