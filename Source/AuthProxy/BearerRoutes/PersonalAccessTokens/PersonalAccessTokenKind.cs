// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;

/// <summary>
/// The classification of a presented credential value against the personal access token namespace.
/// </summary>
public enum PersonalAccessTokenKind
{
    /// <summary>
    /// The value is outside the personal access token namespace.
    /// </summary>
    NotPersonalAccessToken = 0,

    /// <summary>
    /// The value is in the namespace and is a well-formed token with a matching checksum.
    /// </summary>
    Canonical = 1,

    /// <summary>
    /// The value is in the namespace and is not a well-formed token with a matching checksum.
    /// </summary>
    Malformed = 2,
}
