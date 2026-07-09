// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Represents a service that is configured for the back-channel client-credentials flow.
/// </summary>
/// <param name="Name">The configured service key.</param>
/// <param name="RoutePrefix">The route prefix that issued tokens are scoped to.</param>
/// <param name="VerificationUri">The downstream verification endpoint.</param>
public record ConfiguredClientCredentialsService(
    string Name,
    string RoutePrefix,
    Uri VerificationUri);
