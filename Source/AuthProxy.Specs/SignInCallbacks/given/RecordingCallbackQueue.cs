// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.given;

/// <summary>
/// A queue that remembers what was handed to it instead of delivering it.
/// </summary>
public sealed class RecordingCallbackQueue : ISignInCallbackQueue
{
    readonly List<SignInCallbackRequest> _requests = [];

    /// <summary>
    /// Gets the callbacks queued so far.
    /// </summary>
    public IReadOnlyList<SignInCallbackRequest> Requests => _requests;

    /// <summary>
    /// Gets or sets a value indicating whether the queue accepts what it is given.
    /// </summary>
    public bool Accepts { get; set; } = true;

    /// <inheritdoc/>
    public bool TryEnqueue(SignInCallbackRequest request)
    {
        if (!Accepts)
        {
            return false;
        }

        _requests.Add(request);
        return true;
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<SignInCallbackRequest> ReadAll([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.CompletedTask;
        foreach (var request in _requests)
        {
            yield return request;
        }
    }
}
