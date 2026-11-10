// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Provides atomic, deployment-wide consumption of DPoP proof identifiers. Never use a local fallback.</summary>
public interface IDpopReplayStore
{
    /// <summary>Checks store availability, clock alignment and replay coverage before issuing a nonce or accepting a proof.</summary>
    /// <param name="cancellationToken">The request cancellation token.</param>
    /// <returns>The health verdict.</returns>
    Task<DpopReplayResult> CheckHealth(CancellationToken cancellationToken);

    /// <summary>Atomically consumes a key-thumbprint/proof-identifier pair for at least 390 seconds.</summary>
    /// <param name="origin">The trusted configured public origin in the resource validation domain.</param>
    /// <param name="jkt">The verified public-key thumbprint.</param>
    /// <param name="jti">The verified bounded printable proof identifier.</param>
    /// <param name="cancellationToken">The request cancellation token.</param>
    /// <returns>Accepted, replay, or unavailable. Fail closed on any uncertainty.</returns>
    Task<DpopReplayResult> TryConsume(string origin, string jkt, string jti, CancellationToken cancellationToken);
}
