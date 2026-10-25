// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator.given;

public class a_metadata_validated_token : Specification
{
    protected IInvitationTokenKeys Keys;
    protected InviteTokenValidator Validator;
    protected RsaSecurityKey SigningKey;
    protected string Token;
    protected InviteTokenValidationResult Result;
    protected readonly C.Invite Invite = new() { TokenMetadataUrl = "https://lobby.example.com/metadata", Issuer = "issuer", Audience = "audience" };
    protected readonly Dictionary<string, SecurityKey> PublicKeys = new(StringComparer.Ordinal);
    RSA _rsa;

    void Establish()
    {
        _rsa = RSA.Create(2048);
        SigningKey = new RsaSecurityKey(_rsa) { KeyId = "known" };
        PublicKeys.Add("known", new RsaSecurityKey(_rsa.ExportParameters(false)) { KeyId = "known" });
        Keys = Substitute.For<IInvitationTokenKeys>();
        Keys.GetSigningKeys(Invite, Arg.Any<CancellationToken>(), Arg.Any<bool>()).Returns(_ => Task.FromResult<IReadOnlyDictionary<string, SecurityKey>?>(PublicKeys));
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy { Invite = Invite });
        Validator = new InviteTokenValidator(options, Keys);
        Token = CreateToken();
    }

    void Destroy() => _rsa.Dispose();

    protected string CreateToken(string issuer = "issuer", string audience = "audience", DateTime? expires = null, DateTime? notBefore = null) =>
        TokenFixture.CreateToken(SigningKey, issuer, audience, expires, notBefore);

    protected string WithAlgorithm(string algorithm, SecurityKey? key) => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Issuer = "issuer", Audience = "audience", Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = key is null ? null : new SigningCredentials(key, algorithm)
    });
}
