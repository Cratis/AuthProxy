// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Signs forwarded identity for an explicitly identified outbound flow.</summary>
public interface IForwardedIdentitySigner
{
    /// <summary>Removes a stale proof and signs when the flow and request require it.</summary>
    /// <param name="request">The final outbound message.</param>
    /// <param name="target">The selected destination flow.</param>
    /// <returns>The signing decision.</returns>
    ForwardedIdentitySigningOutcome Sign(HttpRequestMessage request, ForwardedIdentitySigningTarget target);
}
