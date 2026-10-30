// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Represents how a freshly received provider ticket is handled.
/// </summary>
enum TicketReceivedRoute
{
    /// <summary>
    /// The canonical identity could not be resolved; the ticket fails.
    /// </summary>
    Fail = 0,

    /// <summary>
    /// The ticket completes an account link rather than a sign-in.
    /// </summary>
    CompleteLink = 1,

    /// <summary>
    /// The ticket completes a normal sign-in.
    /// </summary>
    CompleteSignIn = 2
}
