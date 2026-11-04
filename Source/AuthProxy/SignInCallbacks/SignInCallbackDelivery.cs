// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Delivers queued sign-in callbacks in the background, so no user request ever waits for one.
/// </summary>
/// <param name="queue">The queue the callbacks arrive on.</param>
/// <param name="sender">The system that posts a callback to a service.</param>
public class SignInCallbackDelivery(ISignInCallbackQueue queue, ISignInCallbackSender sender) : BackgroundService
{
    /// <summary>
    /// How many callbacks are delivered at the same time, so one slow service does not hold up the others.
    /// </summary>
    public const int Workers = 4;

    /// <inheritdoc/>
    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        Task.WhenAll(Enumerable.Range(0, Workers).Select(_ => Task.Run(() => Work(stoppingToken), CancellationToken.None)));

    async Task Work(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var request in queue.ReadAll(stoppingToken))
            {
                // The sender never throws; the guard only keeps a worker alive if that is ever broken.
                try
                {
                    await sender.Send(request, stoppingToken);
                }
                catch (Exception) when (!stoppingToken.IsCancellationRequested)
                {
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }
}
