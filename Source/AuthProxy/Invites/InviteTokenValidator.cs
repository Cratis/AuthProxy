// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Validates invite JWT tokens using a pinned RSA key or configured invitation issuer metadata.
/// </summary>
/// <param name="config">The current auth proxy configuration.</param>
/// <param name="tokenKeys">The configured invitation issuer's public keys.</param>
public class InviteTokenValidator(IOptionsMonitor<C.AuthProxy> config, IInvitationTokenKeys tokenKeys) : IInviteTokenValidator
{
    /// <inheritdoc/>
    public async Task<bool> Validate(string token, CancellationToken cancellationToken) =>
        await ValidateDetailed(token, cancellationToken) == InviteTokenValidationResult.Valid;

    /// <inheritdoc/>
    public async Task<InviteTokenValidationResult> ValidateDetailed(string token, CancellationToken cancellationToken)
    {
        var invite = config.CurrentValue.Invite;
        if (invite is null)
        {
            return InviteTokenValidationResult.Invalid;
        }
        return string.IsNullOrWhiteSpace(invite.TokenMetadataUrl)
            ? await ValidateWithPinnedKey(token, invite)
            : await ValidateWithMetadata(token, invite, cancellationToken);
    }

    /// <inheritdoc/>
    public bool TryGetClaim(string token, string claimType, out string claimValue)
    {
        claimValue = string.Empty;
        try
        {
            var handler = new JsonWebTokenHandler();
            var jwt = handler.ReadJsonWebToken(token);
            var claim = jwt.Claims.FirstOrDefault(c => c.Type == claimType);
            if (claim is not null)
            {
                claimValue = claim.Value;
                return true;
            }
        }
        catch (ArgumentException)
        {
            // Token is null, empty, or not a well-formed JWT.
        }

        return false;
    }

    static async Task<InviteTokenValidationResult> ValidateWithPinnedKey(string token, C.Invite invite)
    {
        if (string.IsNullOrWhiteSpace(invite.PublicKeyPem))
        {
            return InviteTokenValidationResult.Invalid;
        }
        RsaSecurityKey securityKey;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(invite.PublicKeyPem);
            securityKey = new RsaSecurityKey(rsa.ExportParameters(false));
        }
        catch
        {
            return InviteTokenValidationResult.Invalid;
        }
        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ValidateIssuer = !string.IsNullOrEmpty(invite.Issuer),
            ValidIssuer = invite.Issuer,
            ValidateAudience = !string.IsNullOrEmpty(invite.Audience),
            ValidAudience = invite.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
        return Map(await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters));
    }

    static JsonWebToken? ReadToken(string token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > InviteCompletion.MaximumAttestedInvitationTokenLength)
        {
            return null;
        }
        try
        {
            var jwt = new JsonWebTokenHandler().ReadJsonWebToken(token);
            return string.Equals(jwt.Alg, InvitationTokenKeys.Algorithm, StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(jwt.Kid) ? jwt : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    static InviteTokenValidationResult Map(TokenValidationResult result) => result.IsValid
        ? InviteTokenValidationResult.Valid
        : result.Exception is SecurityTokenExpiredException ? InviteTokenValidationResult.Expired : InviteTokenValidationResult.Invalid;

    async Task<InviteTokenValidationResult> ValidateWithMetadata(string token, C.Invite invite, CancellationToken cancellationToken)
    {
        var jwt = ReadToken(token);
        if (jwt is null)
        {
            return InviteTokenValidationResult.Invalid;
        }
        var keys = await tokenKeys.GetSigningKeys(invite, cancellationToken);
        if (keys is null)
        {
            return InviteTokenValidationResult.Invalid;
        }
        if (!keys.TryGetValue(jwt.Kid, out var key))
        {
            keys = await tokenKeys.GetSigningKeys(invite, cancellationToken, refresh: true);
            if (keys is null || !keys.TryGetValue(jwt.Kid, out key))
            {
                return InviteTokenValidationResult.Invalid;
            }
        }
        var parameters = new TokenValidationParameters
        {
            IssuerSigningKeys = [key],
            TryAllIssuerSigningKeys = false,
            ValidAlgorithms = [InvitationTokenKeys.Algorithm],
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidIssuer = invite.Issuer,
            ValidateAudience = true,
            ValidAudience = invite.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
        return Map(await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters));
    }
}
