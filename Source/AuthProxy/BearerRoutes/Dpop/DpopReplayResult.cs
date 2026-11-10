// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>The result of a fail-closed shared replay-store operation.</summary>
public enum DpopReplayResult
{
    /// <summary>Availability, clock alignment or replay coverage cannot be guaranteed.</summary>
    Unavailable = 0,

    /// <summary>The store is healthy and the operation succeeded.</summary>
    Accepted = 1,

    /// <summary>The proof identifier was already consumed.</summary>
    Replay = 2,
}
