// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Nodes;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Represents what one service's <c>/.cratis/me</c> call established, and the details it supplied.
/// </summary>
/// <param name="Status">What the service established about the caller.</param>
/// <param name="Reason">The bounded code explaining how that status was reached.</param>
/// <param name="Details">The identity details to merge, empty when the service supplied none.</param>
/// <remarks>
/// Details travel alongside an indeterminate status on purpose. A service answering enrichment data with no
/// verdict has genuinely supplied details and genuinely established nothing, and a deployment asking only
/// for enrichment should still get the details. Separating the two means neither mode has to be expressed
/// by throwing information away.
/// </remarks>
public record IdentityVerificationOutcome(
    IdentityVerificationStatus Status,
    IdentityVerificationReason Reason,
    JsonObject Details)
{
    /// <summary>
    /// Creates an outcome for a service that answered an unambiguous positive verdict.
    /// </summary>
    /// <param name="details">The identity details the service supplied.</param>
    /// <returns>The positive outcome.</returns>
    public static IdentityVerificationOutcome Positive(JsonObject details) =>
        new(IdentityVerificationStatus.Positive, IdentityVerificationReason.Verified, details);

    /// <summary>
    /// Creates an outcome for a service that explicitly refused the caller.
    /// </summary>
    /// <param name="reason">The bounded code explaining the refusal.</param>
    /// <returns>The denied outcome.</returns>
    public static IdentityVerificationOutcome Denied(IdentityVerificationReason reason) =>
        new(IdentityVerificationStatus.Denied, reason, new JsonObject());

    /// <summary>
    /// Creates an outcome for a service that established nothing.
    /// </summary>
    /// <param name="reason">The bounded code explaining why nothing was established.</param>
    /// <param name="details">The identity details the service supplied, if any.</param>
    /// <returns>The indeterminate outcome.</returns>
    public static IdentityVerificationOutcome Indeterminate(IdentityVerificationReason reason, JsonObject? details = null) =>
        new(IdentityVerificationStatus.Indeterminate, reason, details ?? new JsonObject());
}
