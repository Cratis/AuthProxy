// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.Ingress.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.Ingress.Invites;

/// <summary>
/// Validates invite JWT tokens issued by Cratis Studio using a pinned RSA public key.
/// </summary>
/// <param name="config">The options monitor providing the current ingress configuration.</param>
public class InviteTokenValidator(IOptionsMonitor<IngressConfig> config) : IInviteTokenValidator
{
    /// <inheritdoc/>
    public bool Validate(string token)
    {
        var invite = config.CurrentValue.Invite;
        if (invite is null || string.IsNullOrWhiteSpace(invite.PublicKeyPem))
        {
            return false;
        }

        RsaSecurityKey securityKey;
        try
        {
            RSA? rsa = null;
            try
            {
                rsa = RSA.Create();
                rsa.ImportFromPem(invite.PublicKeyPem);
                securityKey = new RsaSecurityKey(rsa.ExportParameters(false));
            }
            finally
            {
                rsa?.Dispose();
            }
        }
        catch
        {
            return false;
        }

        var handler = new JsonWebTokenHandler();
        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,
            ValidateIssuer = !string.IsNullOrEmpty(invite.Issuer),
            ValidIssuer = invite.Issuer,
            ValidateAudience = !string.IsNullOrEmpty(invite.Audience),
            ValidAudience = invite.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        var result = handler.ValidateTokenAsync(token, parameters).GetAwaiter().GetResult();
        return result.IsValid;
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
}
