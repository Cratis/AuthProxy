// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Defines a system that delivers one sign-in callback to a service.
/// </summary>
public interface ISignInCallbackSender
{
    /// <summary>
    /// Posts the callback to the service, waiting at most the request's timeout.
    /// </summary>
    /// <param name="request">The callback to deliver.</param>
    /// <param name="cancellationToken">Cancels the delivery, for example when AuthProxy shuts down.</param>
    /// <returns><see langword="true"/> when the service accepted the callback; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Nothing here throws: every way a delivery can fail is reported as <see langword="false"/> and logged.
    /// </remarks>
    Task<bool> Send(SignInCallbackRequest request, CancellationToken cancellationToken);
}
