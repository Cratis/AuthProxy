// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Trusted response details for a DPoP challenge.</summary>
/// <param name="Status">The fixed machine status.</param>
/// <param name="Scope">The configured required scope.</param>
/// <param name="Nonce">The optional freshly sealed nonce.</param>
internal sealed record DpopChallengeOptions(int Status = StatusCodes.Status401Unauthorized, string? Scope = null, string? Nonce = null);
