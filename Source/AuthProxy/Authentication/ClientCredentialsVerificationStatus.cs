// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The status of the downstream verification request.
/// </summary>
public enum ClientCredentialsVerificationStatus
{
    /// <summary>
    /// The downstream service accepted the client credentials.
    /// </summary>
    Succeeded = 0,

    /// <summary>
    /// The downstream service rejected the client credentials.
    /// </summary>
    Rejected = 1,

    /// <summary>
    /// The downstream verification call failed unexpectedly.
    /// </summary>
    Failed = 2,
}
