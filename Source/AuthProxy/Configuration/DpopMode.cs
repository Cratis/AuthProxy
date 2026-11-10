// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>Controls whether unbound Bearer access tokens remain eligible.</summary>
public enum DpopMode
{
    /// <summary>Requires DPoP for bound tokens while retaining unbound Bearer support.</summary>
    Accept = 0,

    /// <summary>Requires a bound token and DPoP presentation on every request.</summary>
    Require = 1,
}
