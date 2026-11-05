// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Represents what a sign-in callback reports about the user.
/// </summary>
public enum SignInCallbackKind
{
    /// <summary>
    /// The user has just completed an interactive identity-provider sign-in.
    /// </summary>
    SignedIn = 0,

    /// <summary>
    /// The user came back with a session that was already established, and this is its first request in the interval.
    /// </summary>
    Returned = 1
}
