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

    /// <summary>
    /// Records what the sign-in would after validating both tokens. Each claim is placed in the token that legitimately
    /// carries it (<c language="text">iss</c>, <c language="text">sub</c>, <c language="text">auth_time</c>, <c language="text">jti</c>
    /// in the identity token, the rest in the access token); a <c language="text">sub</c> goes into both.
    /// </summary>
    /// <param name="scheme">The scheme that validated the tokens.</param>
    /// <param name="claims">The claims inside the validated tokens.</param>
    protected void TheHandlerValidated(string scheme, params (string Name, object Value)[] claims)
    {
        string[] identityClaims = ["iss", "sub", "auth_time", "jti"];
        TheHandlerValidated(
            scheme,
            claims.Where(_ => identityClaims.Contains(_.Name)).ToArray(),
            claims.Where(_ => !identityClaims.Contains(_.Name) || _.Name == "sub").ToArray());
    }

    /// <summary>Records what the sign-in would after validating an identity token and an access token with exactly these claims.</summary>
    /// <param name="scheme">The scheme that validated the tokens.</param>
    /// <param name="identityToken">The claims inside the validated identity token.</param>
    /// <param name="accessToken">The claims inside the validated access token, or <see langword="null"/> when none was validated.</param>
    protected void TheHandlerValidated(string scheme, (string Name, object Value)[] identityToken, (string Name, object Value)[]? accessToken)
    {
        VerifiedUpstreamClaims.Capture(_httpContext, scheme, Read(identityToken), accessToken is null ? null : Read(accessToken));
    }

    static JsonWebToken Read((string Name, object Value)[] claims) =>
        new JsonWebTokenHandler().ReadJsonWebToken(new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims.ToDictionary(_ => _.Name, _ => _.Value),
        }));

    protected JsonElement PostedBody() => JsonDocument.Parse(_handler.LastRequestBytes.ToArray()).RootElement;

    protected bool PostedVerifiedClaims(out JsonElement claims) => PostedBody().TryGetProperty("verifiedClaims", out claims);
}
