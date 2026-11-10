// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// The authenticating account's email together with the provider's verification status for it.
/// </summary>
/// <param name="Address">The authenticated email address, or an empty string when none is available.</param>
/// <param name="Verified">
/// The provider's <c language="text">email_verified</c> value: <see langword="true"/>, <see langword="false"/>, or
/// <see langword="null"/> when the provider supplies no independent verification claim.
/// </param>
readonly record struct AuthenticatedEmail(string Address, bool? Verified)
{
    /// <summary>
    /// Determines whether the provider flagged the email as unverified or the address differs from an invited one.
    /// </summary>
    /// <param name="invitedEmail">The email address the invitation targets.</param>
    /// <returns><see langword="true"/> when the account does not own the invited email; otherwise <see langword="false"/>.</returns>
    public bool IsUnverifiedOrDifferentFrom(string invitedEmail) =>
        Verified == false
        || !string.Equals(invitedEmail, Address, StringComparison.OrdinalIgnoreCase);
}
