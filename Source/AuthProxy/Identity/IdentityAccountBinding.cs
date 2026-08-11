// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Identifies the authenticated account whose positive identity state may be reused.
/// </summary>
/// <remarks>
/// Canonical accounts are the complete provider, normalized issuer, and subject tuple. Legacy accounts retain
/// the released user-identifier-only behavior. The record itself is used as a structured cache-key component,
/// so no caller-visible value can change field boundaries through delimiter content.
/// </remarks>
internal sealed record IdentityAccountBinding
{
    const string CanonicalKind = "canonical-v1";
    const string LegacyKind = "legacy-v1";
    const string ReservedClaimPrefix = "urn:cratis:identity:";

    /// <summary>
    /// Initializes a structured account binding.
    /// </summary>
    /// <param name="kind">The versioned binding kind.</param>
    /// <param name="providerKey">The canonical provider key, or an empty value for legacy.</param>
    /// <param name="issuer">The canonical issuer, or an empty value for legacy.</param>
    /// <param name="subject">The canonical subject or legacy user identifier.</param>
    public IdentityAccountBinding(string kind, string providerKey, string issuer, string subject)
    {
        Kind = kind;
        ProviderKey = providerKey;
        Issuer = issuer;
        Subject = subject;
    }

    /// <summary>
    /// Gets the versioned binding kind.
    /// </summary>
    public string Kind { get; init; }

    /// <summary>
    /// Gets the canonical provider key, or an empty value for a legacy binding.
    /// </summary>
    public string ProviderKey { get; init; }

    /// <summary>
    /// Gets the canonical normalized issuer, or an empty value for a legacy binding.
    /// </summary>
    public string Issuer { get; init; }

    /// <summary>
    /// Gets the canonical subject or legacy user identifier.
    /// </summary>
    public string Subject { get; init; }

    /// <summary>
    /// Gets a value indicating whether this is a canonical binding.
    /// </summary>
    public bool IsCanonical => string.Equals(Kind, CanonicalKind, StringComparison.Ordinal);

    /// <summary>
    /// Gets an identifier safe for identity resolver logs.
    /// </summary>
    /// <returns>An opaque label naming the kind of binding, never the account's own identity.</returns>
    /// <remarks>
    /// A legacy binding's <see cref="Subject"/> is the raw provider-supplied user identifier, and legacy is
    /// what every provider that has not opted into canonical identity resolves to — which is the default.
    /// Returning it here put that identifier into every identity-resolution log line, so the label is opaque
    /// for both kinds and the identifier has no way back into a log message.
    /// </remarks>
    public string GetLogIdentifier() => IsCanonical ? "canonical-account" : "legacy-account";

    /// <summary>
    /// Attempts to create a reusable account binding from a client principal.
    /// </summary>
    /// <param name="principal">The client principal to validate.</param>
    /// <param name="binding">The validated account binding when successful.</param>
    /// <returns><see langword="true"/> when the principal is legacy without reserved claims or carries one valid canonical tuple; otherwise <see langword="false"/>.</returns>
    public static bool TryCreate(ClientPrincipal principal, out IdentityAccountBinding binding)
    {
        var reservedClaims = principal.Claims
            .Where(claim => claim.Type.StartsWith(ReservedClaimPrefix, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (reservedClaims.Length == 0)
        {
            binding = new(LegacyKind, string.Empty, string.Empty, principal.UserId);
            return true;
        }

        if (reservedClaims.Length != CanonicalIdentityClaims.All.Length
            || !TryGetSingleExactClaim(reservedClaims, CanonicalIdentityClaims.ProviderKey, out var providerKey)
            || !TryGetSingleExactClaim(reservedClaims, CanonicalIdentityClaims.Issuer, out var issuer)
            || !TryGetSingleExactClaim(reservedClaims, CanonicalIdentityClaims.Subject, out var subject)
            || !CanonicalIssuer.TryNormalize(issuer, out var normalizedIssuer)
            || !string.Equals(issuer, normalizedIssuer, StringComparison.Ordinal)
            || !string.Equals(providerKey, principal.IdentityProvider, StringComparison.Ordinal)
            || !string.Equals(subject, principal.UserId, StringComparison.Ordinal))
        {
            binding = null!;
            return false;
        }

        binding = new(CanonicalKind, providerKey, normalizedIssuer, subject);
        return true;
    }

    static bool TryGetSingleExactClaim(IEnumerable<ClientPrincipalClaim> claims, string claimType, out string value)
    {
        var matches = claims.Where(claim => string.Equals(claim.Type, claimType, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length != 1
            || !string.Equals(matches[0].Type, claimType, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(matches[0].Value)
            || !string.Equals(matches[0].Value, matches[0].Value.Trim(), StringComparison.Ordinal)
            || matches[0].Value.Length > 2048)
        {
            value = string.Empty;
            return false;
        }

        value = matches[0].Value;
        return true;
    }
}
