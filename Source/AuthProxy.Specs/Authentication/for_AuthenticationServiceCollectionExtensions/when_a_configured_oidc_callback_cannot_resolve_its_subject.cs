// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that an invalid configured OIDC callback fails the authentication context.
/// </summary>
public class when_a_configured_oidc_callback_cannot_resolve_its_subject : configured_canonical_provider_callbacks
{
    TicketReceivedContext _ticketContext;

    async Task Because()
    {
        var context = Context();
        var properties = new AuthenticationProperties();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "wrong-subject-claim")], "microsoft"));
        var scheme = new AuthenticationScheme("microsoft", "microsoft", typeof(OpenIdConnectHandler));
        var tokenContext = new TokenValidatedContext(context, scheme, _oidcOptions, principal, properties)
        {
            SecurityToken = new JwtSecurityToken(issuer: ValidatedIssuer)
        };
        await _oidcOptions.Events.OnTokenValidated(tokenContext);
        _ticketContext = TicketContext(context, "microsoft", _oidcOptions, principal, properties);
        await _oidcOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_fail_the_callback() => _ticketContext.Result!.Failure.ShouldNotBeNull();
    [Fact] void should_not_apply_an_enriched_principal() => _ticketContext.Principal!.FindFirst(CanonicalIdentityClaims.ProviderKey).ShouldBeNull();
}
