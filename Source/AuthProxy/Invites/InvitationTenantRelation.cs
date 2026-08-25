// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Describes the observed relation between an invitation's configured tenant claim and the tenant resolved for
/// the current request.
/// </summary>
internal enum InvitationTenantRelation
{
    /// <summary>
    /// One or both tenant values could not be resolved, so their relation is unknown.
    /// </summary>
    Unresolved = 0,

    /// <summary>
    /// Both tenant values were resolved and are equal.
    /// </summary>
    Matching = 1,

    /// <summary>
    /// Both tenant values were resolved and are different.
    /// </summary>
    NonMatching = 2,
}
