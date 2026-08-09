// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Defines the claim type identifiers AuthProxy reserves for canonical federated identity metadata.
/// </summary>
/// <remarks>
/// AuthProxy removes case-insensitive producer collisions before adding exactly one value for each claim after
/// successful canonical resolution. Their presence describes the authenticated provider account; it does not grant
/// application membership, roles, scopes, authorization, or ownership of the subject value.
/// </remarks>
public static class CanonicalIdentityClaims
{
    /// <summary>
    /// The claim type for the stable configured provider key, independent of the provider display name and scheme.
    /// </summary>
    public const string ProviderKey = "urn:cratis:identity:provider-key";

    /// <summary>
    /// The claim type for the normalized issuer associated with the authenticated provider account.
    /// </summary>
    public const string Issuer = "urn:cratis:identity:issuer";

    /// <summary>
    /// The claim type for the exact provider subject selected by canonical identity configuration.
    /// </summary>
    public const string Subject = "urn:cratis:identity:subject";

    /// <summary>
    /// Gets all claim types reserved for AuthProxy-authored canonical identity metadata.
    /// </summary>
    internal static readonly string[] All = [ProviderKey, Issuer, Subject];

    /// <summary>
    /// Determines whether a claim type belongs to the namespace reserved for AuthProxy-authored canonical identity metadata.
    /// </summary>
    /// <param name="claimType">The claim type to inspect.</param>
    /// <returns><see langword="true"/> when <paramref name="claimType"/> is in the reserved namespace; otherwise <see langword="false"/>.</returns>
    internal static bool IsReserved(string claimType)
    {
        const string reservedPrefix = "urn:cratis:identity:";

        return claimType.StartsWith(reservedPrefix, StringComparison.OrdinalIgnoreCase);
    }
}
