// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Defines how AuthProxy answers a signed-in person whom the identity details of a service deny.
/// </summary>
public enum OidcDenialResponse
{
    /// <summary>
    /// The denial is answered with the forbidden page. This is the default.
    /// </summary>
    Forbidden = 0,

    /// <summary>
    /// The denial is answered like a failed sign-in: the session is terminated and the person is sent to provider
    /// selection with the same reason a failed sign-in carries, so the two cannot be told apart.
    /// </summary>
    FailedSignIn = 1,
}
