// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Defines a validator for invite JWT tokens issued by Cratis Studio.
/// </summary>
public interface IInviteTokenValidator
{
    /// <summary>
    /// Validates the invite <paramref name="token"/> against the configured public key and claims.
    /// </summary>
    /// <param name="token">The raw JWT string to validate.</param>
    /// <returns><see langword="true"/> if the token is valid; otherwise <see langword="false"/>.</returns>
    bool Validate(string token);

    /// <summary>
    /// Validates the invite <paramref name="token"/> and returns a detailed <see cref="InviteTokenValidationResult"/>
    /// that distinguishes between a well-formed but expired token and one that is outright invalid.
    /// </summary>
    /// <param name="token">The raw JWT string to validate.</param>
    /// <returns>
    /// <see cref="InviteTokenValidationResult.Valid"/> if the token passes all checks;
    /// <see cref="InviteTokenValidationResult.Expired"/> if the token was validly signed but has expired;
    /// <see cref="InviteTokenValidationResult.Invalid"/> for any other failure (bad signature, malformed, etc.).
    /// </returns>
    InviteTokenValidationResult ValidateDetailed(string token);

    /// <summary>
    /// Reads the value of a named claim directly from the token payload without re-validating the signature.
    /// </summary>
    /// <param name="token">The raw JWT string.</param>
    /// <param name="claimType">The claim type to look up.</param>
    /// <param name="claimValue">The claim value if found; empty string otherwise.</param>
    /// <returns><see langword="true"/> if the claim was found; otherwise <see langword="false"/>.</returns>
    bool TryGetClaim(string token, string claimType, out string claimValue);
}
