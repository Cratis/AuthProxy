// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

public class a_recipient_mode_capability : Specification
{
    protected static string Capability(params Claim[] claims)
    {
        var (signingKey, _) = TokenFixture.GenerateKeyPair();
        return TokenFixture.CreateToken(
            signingKey,
            "invite-authority",
            "authproxy",
            additionalClaims: claims);
    }
}
