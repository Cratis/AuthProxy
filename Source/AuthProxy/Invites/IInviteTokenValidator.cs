// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Defines a validator for invite JWT tokens issued by Cratis Studio.
/// </summary>
public interface IInviteTokenValidator
{
    /// <summary>
    /// Validates an invitation token asynchronously, including issuer key retrieval when configured.
    /// </summary>
    /// <param name="token">The raw JWT string to validate.</param>
    /// <param name="cancellationToken">Cancellation of the request.</param>
    /// <returns>Whether the token passes all checks.</returns>
    Task<bool> Validate(string token, CancellationToken cancellationToken);

    /// <summary>
    /// Validates an invitation token asynchronously and distinguishes validly signed expiry from invalid input.
    /// </summary>
    /// <param name="token">The raw JWT string to validate.</param>
    /// <param name="cancellationToken">Cancellation of the request.</param>
    /// <returns>The detailed validation result.</returns>
    Task<InviteTokenValidationResult> ValidateDetailed(string token, CancellationToken cancellationToken);

    /// <summary>
    /// Reads the value of a named claim directly from the token payload without re-validating the signature.
    /// </summary>
    /// <param name="token">The raw JWT string.</param>
    /// <param name="claimType">The claim type to look up.</param>
    /// <param name="claimValue">The claim value if found; empty string otherwise.</param>
    /// <returns><see langword="true"/> if the claim was found; otherwise <see langword="false"/>.</returns>
    bool TryGetClaim(string token, string claimType, out string claimValue);
}
