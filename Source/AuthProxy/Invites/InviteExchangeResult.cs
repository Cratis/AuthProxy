// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Represents the outcome of an invite exchange request.
/// </summary>
enum InviteExchangeResult
{
    /// <summary>The exchange completed successfully.</summary>
    Success = 0,

    /// <summary>The exchange was rejected because the subject is already associated with an existing user (HTTP 409).</summary>
    DuplicateSubject = 1,

    /// <summary>The exchange failed for any other reason.</summary>
    Failed = 2,
}
