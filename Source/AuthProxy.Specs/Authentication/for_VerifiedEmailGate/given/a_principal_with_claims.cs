// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_VerifiedEmailGate.given;

/// <summary>
/// Provides a way to ask the gate about a principal that carries exactly the claims a spec lists.
/// </summary>
public class a_principal_with_claims : Specification
{
    protected static bool Satisfied(params (string Type, string Value)[] claims) =>
        VerifiedEmailGate.IsSatisfied(
            new ClaimsPrincipal(new ClaimsIdentity(claims.Select(_ => new Claim(_.Type, _.Value)), "test")),
            VerifiedEmailGate.DefaultEmailClaimType,
            VerifiedEmailGate.DefaultEmailVerifiedClaimType,
            includeMappedEmail: true);
}
