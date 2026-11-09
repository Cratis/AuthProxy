// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Represents the kinds of credential a bearer route accepts, which decides what its refusals advertise.
/// </summary>
public enum BearerProfile
{
    /// <summary>
    /// The route accepts signed OAuth access tokens only and advertises its protected-resource metadata.
    /// </summary>
    OAuthOnly = 0,

    /// <summary>
    /// The route accepts personal access tokens only; it advertises a realm and no OAuth metadata at all.
    /// </summary>
    PatOnly = 1,

    /// <summary>
    /// The route accepts both kinds and advertises its protected-resource metadata.
    /// </summary>
    Combined = 2,
}
