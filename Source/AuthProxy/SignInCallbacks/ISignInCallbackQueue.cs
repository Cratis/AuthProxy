// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Defines the bounded queue that carries sign-in callbacks from the request that caused them to the background delivery.
/// </summary>
public interface ISignInCallbackQueue
{
    /// <summary>
    /// Adds a callback to the queue without waiting.
    /// </summary>
    /// <param name="request">The callback to deliver.</param>
    /// <returns><see langword="true"/> when it was queued; <see langword="false"/> when the queue is full and the callback was dropped.</returns>
    bool TryEnqueue(SignInCallbackRequest request);

    /// <summary>
    /// Reads callbacks as they arrive, until cancelled.
    /// </summary>
    /// <param name="cancellationToken">Ends the reading.</param>
    /// <returns>The queued callbacks, in order.</returns>
    IAsyncEnumerable<SignInCallbackRequest> ReadAll(CancellationToken cancellationToken);
}
