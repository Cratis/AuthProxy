// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Represents a validated access token's DPoP public-key confirmation.</summary>
/// <param name="Jkt">The canonical SHA-256 JWK thumbprint.</param>
public sealed record DpopSenderConstraint(string Jkt);
