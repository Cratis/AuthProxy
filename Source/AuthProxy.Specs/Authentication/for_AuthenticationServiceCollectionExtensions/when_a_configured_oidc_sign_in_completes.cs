// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a completed OIDC sign-in records its provider scheme on the session.
/// </summary>
public class when_a_configured_oidc_sign_in_completes : configured_canonical_provider_callbacks
{
    TicketReceivedContext _ticketContext;

    async Task Because()
    {
        var context = Context();
        var properties = new AuthenticationProperties();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "subject-1")], "AuthenticationTypes.Federation"));
        var scheme = new AuthenticationScheme("microsoft", "microsoft", typeof(OpenIdConnectHandler));
        await _oidcOptions.Events.OnTokenValidated(new TokenValidatedContext(context, scheme, _oidcOptions, principal, properties)
        {
            SecurityToken = new JwtSecurityToken(issuer: "https://login.example.test/")
        });
        _ticketContext = TicketContext(context, "microsoft", _oidcOptions, principal, properties);
        await _oidcOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_record_exactly_one_provider_scheme() => _ticketContext.Principal.FindAll(SessionClaims.ProviderScheme).Count().ShouldEqual(1);
    [Fact] void should_record_the_oidc_scheme() => _ticketContext.Principal.FindFirst(SessionClaims.ProviderScheme).Value.ShouldEqual("microsoft");
}
