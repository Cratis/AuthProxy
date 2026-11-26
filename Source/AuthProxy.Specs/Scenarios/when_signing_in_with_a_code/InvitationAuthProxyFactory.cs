// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Scenarios.when_signing_in_with_a_code;

public class InvitationAuthProxyFactory : AuthProxyFactory
{
    readonly (RsaSecurityKey PrivateKey, string PublicKeyPem) _keys = TokenFixture.GenerateKeyPair();

    public string InvitationFor(string email, string invitationId = "9f6b3c0a-0000-4000-8000-000000000001") =>
        TokenFixture.CreateToken(
            _keys.PrivateKey,
            "ante",
            "authproxy",
            additionalClaims:
            [
                new Claim("email", email),
                new Claim("jti", invitationId),
                new Claim("tenant_id", TenantId),
            ]);

    protected override IEnumerable<KeyValuePair<string, string?>> ExtraSettings =>
    [
        new($"{C.AuthProxy.SectionKey}:Invite:PublicKeyPem", _keys.PublicKeyPem),
        new($"{C.AuthProxy.SectionKey}:Invite:Issuer", "ante"),
        new($"{C.AuthProxy.SectionKey}:Invite:Audience", "authproxy"),
        new($"{C.AuthProxy.SectionKey}:Invite:ExchangeUrl", "https://example.test/_invite/exchange"),
        new($"{C.AuthProxy.SectionKey}:Invite:EmailClaim", "email"),
        new($"{C.AuthProxy.SectionKey}:Invite:TenantClaim", "tenant_id"),
    ];
}
