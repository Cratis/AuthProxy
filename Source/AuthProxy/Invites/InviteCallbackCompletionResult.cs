// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Tells the provider-callback handler what <see cref="InviteCallbackCompletion"/> decided, and therefore
/// what remains for the handler to do.
/// </summary>
enum InviteCallbackCompletionResult
{
    /// <summary>
    /// The callback does not answer a pending invitation's own challenge — or its outcome is deliberately
    /// left to the post-login middleware. The handler proceeds exactly as before invitations completed on
    /// the callback.
    /// </summary>
    NotCompleted = 0,

    /// <summary>
    /// The invitation completed and the browser stays on the challenge's own return URL, so the handler's
    /// normal post-sign-in redirect resolution still applies.
    /// </summary>
    CompletedTowardReturnUrl = 1,

    /// <summary>
    /// The invitation reached a terminal answer and the redirect target has been decided — the handler signs
    /// the session in and redirects there, resolving nothing further.
    /// </summary>
    CompletedWithRedirect = 2,

    /// <summary>
    /// The response has been written and the remote handler must not touch it further; the session was
    /// signed in here before answering.
    /// </summary>
    ResponseHandled = 3,
}
