// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

/// <summary>
/// A signed notifier with <c language="text">SignIn:IncludeVerifiedUpstreamClaims</c> switched on (or off, by a derived spec).
/// </summary>
public class a_verified_claims_sign_in_notifier : a_signed_sign_in_notifier
{
    protected const string Scheme = "oidc-upstream";

    protected virtual bool IncludesVerifiedClaims => true;

    protected override C.AuthProxy CreateConfig()
    {
        var configuration = base.CreateConfig();
        configuration.SignIn.IncludeVerifiedUpstreamClaims = IncludesVerifiedClaims;
        return configuration;
    }

    /// <summary>Records what the OpenID Connect handler would after validating an identity token with these claims.</summary>
    /// <param name="scheme">The scheme that validated the token.</param>
    /// <param name="claims">The claims inside the validated token.</param>
    protected void TheHandlerValidated(string scheme, params (string Name, object Value)[] claims)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = claims.ToDictionary(_ => _.Name, _ => _.Value),
        };
        var token = new JsonWebTokenHandler().ReadJsonWebToken(new JsonWebTokenHandler().CreateToken(descriptor));
        VerifiedUpstreamClaims.Capture(_httpContext, scheme, token);
    }

    protected JsonElement PostedBody() => JsonDocument.Parse(_handler.LastRequestBytes.ToArray()).RootElement;

    protected bool PostedVerifiedClaims(out JsonElement claims) => PostedBody().TryGetProperty("verifiedClaims", out claims);
}
