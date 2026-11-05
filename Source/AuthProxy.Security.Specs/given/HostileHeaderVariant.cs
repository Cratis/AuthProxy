// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Header spellings and multiplicities supplied by a caller.
/// </summary>
public enum HostileHeaderVariant
{
    /// <summary>Canonical names.</summary>
    Exact = 0,

    /// <summary>Uppercase names.</summary>
    Upper = 1,

    /// <summary>Mixed-case names.</summary>
    Mixed = 2,

    /// <summary>Repeated values.</summary>
    Duplicated = 3,

    /// <summary>Repeated names differing in case.</summary>
    CaseDuplicated = 4,

    /// <summary>Underscore spellings.</summary>
    Underscored = 5
}
