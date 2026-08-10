// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Represents provider-derived identity evidence verified by AuthProxy for invitation completion.
/// </summary>
/// <param name="ProviderKey">The configured canonical provider key.</param>
/// <param name="ProviderIssuer">The normalized provider issuer.</param>
/// <param name="ProviderSubject">The provider subject.</param>
/// <param name="Email">The verified provider-derived email, or <see langword="null"/> for an immutable provider-subject binding.</param>
/// <param name="Assurance">The provider-derived authentication assurance.</param>
/// <param name="AuthenticatedAt">The time at which provider authentication completed.</param>
public sealed record InvitationVerifiedIdentity(
    string ProviderKey,
    string ProviderIssuer,
    string ProviderSubject,
    string? Email,
    string Assurance,
    DateTimeOffset AuthenticatedAt);
