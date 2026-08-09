// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that the validated OIDC token issuer, rather than a spoofed principal claim, binds the callback identity.
/// </summary>
public class when_a_configured_oidc_callback_receives_a_validated_token : configured_canonical_provider_callbacks
{
    TicketReceivedContext _ticketContext;

    async Task Because()
    {
        var context = Context();
        var properties = new AuthenticationProperties();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("oid", "subject-42"),
            new Claim("iss", "https://spoofed.example.com")
        ],
        "microsoft"));
        var scheme = new AuthenticationScheme("microsoft", "microsoft", typeof(OpenIdConnectHandler));
        var tokenContext = new TokenValidatedContext(context, scheme, _oidcOptions, principal, properties)
        {
            SecurityToken = new JwtSecurityToken(issuer: ValidatedIssuer)
        };
        await _oidcOptions.Events.OnTokenValidated(tokenContext);
        _ticketContext = TicketContext(context, "microsoft", _oidcOptions, principal, properties);
        await _oidcOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_apply_the_enriched_principal() => _ticketContext.Principal!.FindFirst(CanonicalIdentityClaims.ProviderKey)!.Value.ShouldEqual("entra-workforce");
    [Fact] void should_use_the_framework_validated_token_issuer() => _ticketContext.Principal!.FindFirst(CanonicalIdentityClaims.Issuer)!.Value.ShouldEqual(ValidatedIssuer);
    [Fact] void should_not_use_the_spoofed_issuer_claim() => _ticketContext.Principal!.FindFirst(CanonicalIdentityClaims.Issuer)!.Value.ShouldNotEqual("https://spoofed.example.com");
}
