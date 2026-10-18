// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// Signs the identity and tenant headers of a request AuthProxy sends to a service.
/// </summary>
/// <remarks>
/// Every request AuthProxy sends to a service on a caller's behalf goes through this — the proxied request
/// itself and every back-channel call carrying identity headers — so a verifying backend never has to
/// distinguish a proxied request from a back-channel one.
/// </remarks>
public interface IForwardedIdentitySigner
{
    /// <summary>
    /// Gets a value indicating whether signed forwarding is configured.
    /// </summary>
    bool IsEnabled { get; }

    /// <summary>
    /// Gets the audience assertions for a configured service are signed for.
    /// </summary>
    /// <param name="serviceName">The configuration key of the service.</param>
    /// <returns>The service's forwarding audience, or its key when it states none.</returns>
    string AudienceFor(string serviceName);

    /// <summary>
    /// Signs a request exactly as it is about to be sent.
    /// </summary>
    /// <param name="request">
    /// The outbound request, with an absolute <see cref="HttpRequestMessage.RequestUri"/> and every identity and tenant
    /// header already set to the value it will be sent with.
    /// </param>
    /// <param name="audience">The audience of the target service.</param>
    /// <returns>Whether the request was signed, signing is not configured, or signing failed.</returns>
    /// <remarks>
    /// Never throws. <see cref="ForwardedIdentitySigningStatus.Failed"/> means the request must not be sent.
    /// </remarks>
    ForwardedIdentitySigningStatus Sign(HttpRequestMessage request, string audience);
}
