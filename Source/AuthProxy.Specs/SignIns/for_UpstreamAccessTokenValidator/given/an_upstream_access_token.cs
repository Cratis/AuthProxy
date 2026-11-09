// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_UpstreamAccessTokenValidator.given;

/// <summary>
/// An identity token the handler already validated, and a provider that signs access tokens with a key it publishes.
/// A derived spec changes one thing about the access token and validates it.
/// </summary>
public class an_upstream_access_token : Specification
{
    protected const string Issuer = "https://idp.example.com";
    protected const string ClientId = "authproxy-client";

    protected static readonly RsaSecurityKey PublishedKey = CreateKey("published");
    protected static readonly RsaSecurityKey OtherKey = CreateKey("other");

    protected JsonWebToken _identityToken;
    protected ILogger _logger;
    protected List<bool> _keyRequests;
    protected JsonWebToken? _result;

    protected virtual string TokenIssuer => Issuer;

    protected virtual string TokenAudience => ClientId;

    protected virtual string TokenType => "at+jwt";

    protected virtual SecurityKey SigningKey => PublishedKey;

    protected virtual DateTime Expires => DateTime.UtcNow.AddMinutes(10);

    protected virtual DateTime? NotBefore => null;

    protected virtual string SigningAlgorithm => SecurityAlgorithms.RsaSha256;

    protected virtual IReadOnlyCollection<SecurityKey> PublishedKeys => [PublishedKey];

    /// <summary>Gets the keys returned after a refresh was requested, when the provider has rotated.</summary>
    protected virtual IReadOnlyCollection<SecurityKey> RotatedKeys => PublishedKeys;

    protected static RsaSecurityKey CreateKey(string keyId) => new(RSA.Create(2048)) { KeyId = keyId };

    protected string CreateAccessToken(IDictionary<string, object>? claims = null)
    {
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = TokenIssuer,
            Audience = TokenAudience,
            Expires = Expires,
            NotBefore = NotBefore,
            TokenType = TokenType,
            SigningCredentials = new SigningCredentials(SigningKey, SigningAlgorithm),
            Claims = claims ?? new Dictionary<string, object> { ["sub"] = "acct-1", ["github_id"] = "777" },
        });
    }

    protected Task<JsonWebToken?> Validate(string? accessToken) =>
        UpstreamAccessTokenValidator.Validate(
            accessToken,
            _identityToken,
            [ClientId],
            TimeSpan.FromSeconds(30),
            refresh =>
            {
                _keyRequests.Add(refresh);
                return Task.FromResult(refresh ? RotatedKeys : PublishedKeys);
            },
            _logger);

    void Establish()
    {
        _keyRequests = [];
        _logger = Substitute.For<ILogger>();
        _logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        _identityToken = new JsonWebTokenHandler().ReadJsonWebToken(new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Claims = new Dictionary<string, object> { ["sub"] = "acct-1" },
        }));
    }
}
