// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;

/// <summary>
/// Which branch a presented credential is handled by. Each credential is handled by exactly one branch and is
/// never retried as the other kind.
/// </summary>
public enum CredentialDispatch
{
    /// <summary>
    /// No bearer credential was presented.
    /// </summary>
    Missing = 0,

    /// <summary>
    /// The credential is handled by OAuth access-token validation.
    /// </summary>
    OAuth = 1,

    /// <summary>
    /// The credential is a well-formed personal access token for this route's resource, to be handed to the service.
    /// </summary>
    PersonalAccessToken = 2,

    /// <summary>
    /// The credential is refused without being offered to the other branch.
    /// </summary>
    Refused = 3,

    /// <summary>
    /// More than one credential was presented, so neither branch is chosen.
    /// </summary>
    Ambiguous = 4,

    /// <summary>
    /// The credential is an access token AuthProxy issued through its client-credentials grant, verified as such, and
    /// is judged by the client-credentials rules only.
    /// </summary>
    ClientCredentials = 5,
}
