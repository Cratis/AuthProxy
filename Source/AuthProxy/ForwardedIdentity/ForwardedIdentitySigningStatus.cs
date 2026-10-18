// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// The outcome of signing an outbound request.
/// </summary>
public enum ForwardedIdentitySigningStatus
{
    /// <summary>
    /// Signed forwarding is not configured; the request is sent unsigned, as it always was.
    /// </summary>
    NotConfigured = 0,

    /// <summary>
    /// The request carries a fresh assertion.
    /// </summary>
    Attested = 1,

    /// <summary>
    /// Signing is configured but the request could not be signed, so it must not be sent.
    /// </summary>
    Failed = 2
}
