// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Represents the provider-aware identity assertion produced from a successfully authenticated principal.
/// </summary>
/// <param name="ProviderKey">The stable configured provider key.</param>
/// <param name="NormalizedIssuer">The strictly normalized provider issuer.</param>
/// <param name="Subject">The exact value of the configured subject claim.</param>
/// <remarks>
/// The tuple identifies an authenticated provider account. It does not assert application membership,
/// authorization, roles, scopes, or that the subject is stable across different provider client registrations.
/// </remarks>
public sealed record CanonicalFederatedIdentity(string ProviderKey, string NormalizedIssuer, string Subject);
