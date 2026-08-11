// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Defines the system that signs the envelope authenticating a sign-in notification to the application.
/// </summary>
public interface ISignInNotificationSigner
{
    /// <summary>
    /// Gets a value indicating whether sign-in notifications are configured to be signed.
    /// </summary>
    /// <remarks>
    /// When this is <see langword="false"/> a notification is posted exactly as it always has been — unsigned,
    /// with no <c>Authorization</c> header. When it is <see langword="true"/> an unsigned notification is never
    /// an acceptable outcome: a caller that cannot obtain an envelope must refuse to post at all.
    /// </remarks>
    bool IsEnabled { get; }

    /// <summary>
    /// Tries to issue the signed envelope binding one notification request.
    /// </summary>
    /// <param name="method">The HTTP method of the request the envelope accompanies.</param>
    /// <param name="target">The absolute target URI of the request the envelope accompanies.</param>
    /// <param name="body">The exact request body bytes the envelope accompanies.</param>
    /// <param name="attestation">The compact signed JWS when successful; otherwise an empty string.</param>
    /// <returns><see langword="true"/> when the envelope was issued; otherwise <see langword="false"/>.</returns>
    bool TryIssue(HttpMethod method, Uri target, byte[] body, out string attestation);
}
