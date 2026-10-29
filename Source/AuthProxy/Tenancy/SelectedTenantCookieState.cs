// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Describes what the selected-tenant cookie of a request holds.
/// </summary>
public enum SelectedTenantCookieState
{
    /// <summary>
    /// The request carries no selected-tenant cookie.
    /// </summary>
    None = 0,

    /// <summary>
    /// The cookie is signed and was written for the signed-in account.
    /// </summary>
    Bound = 1,

    /// <summary>
    /// The cookie holds a plain tenant identifier written by an earlier version.
    /// </summary>
    Legacy = 2,

    /// <summary>
    /// The cookie cannot be trusted: it was altered, written for another account or holds an unusable identifier.
    /// </summary>
    Invalid = 3,
}
