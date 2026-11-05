// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading.Channels;

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// A bounded in-memory <see cref="ISignInCallbackQueue"/>. When it is full the newest callback is dropped, so a service
/// that stops answering can never make the proxy hold an unbounded backlog.
/// </summary>
public class SignInCallbackQueue : ISignInCallbackQueue
{
    /// <summary>
    /// The most callbacks waiting for delivery at one time.
    /// </summary>
    public const int Capacity = 1024;

    readonly Channel<SignInCallbackRequest> _channel = Channel.CreateBounded<SignInCallbackRequest>(
        new BoundedChannelOptions(Capacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleWriter = false,
            SingleReader = false
        });

    /// <inheritdoc/>
    public bool TryEnqueue(SignInCallbackRequest request) => _channel.Writer.TryWrite(request);

    /// <inheritdoc/>
    public IAsyncEnumerable<SignInCallbackRequest> ReadAll(CancellationToken cancellationToken) =>
        _channel.Reader.ReadAllAsync(cancellationToken);
}
