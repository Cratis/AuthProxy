// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a session claim supplied by a provider is replaced by the scheme that completed the sign-in.
/// </summary>
public class when_a_provider_supplies_a_session_provider_claim : configured_canonical_provider_callbacks
{
    TicketReceivedContext _ticketContext;

    async Task Because()
    {
        var context = Context();
        var properties = new AuthenticationProperties();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "subject-1"), new Claim(SessionClaims.ProviderScheme, "github")], "AuthenticationTypes.Federation"));
        var scheme = new AuthenticationScheme("microsoft", "microsoft", typeof(OpenIdConnectHandler));
        await _oidcOptions.Events.OnTokenValidated(new TokenValidatedContext(context, scheme, _oidcOptions, principal, properties)
        {
            SecurityToken = new JwtSecurityToken(issuer: "https://login.example.test/")
        });
        _ticketContext = TicketContext(context, "microsoft", _oidcOptions, principal, properties);
        await _oidcOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_keep_exactly_one_provider_scheme() => _ticketContext.Principal.FindAll(SessionClaims.ProviderScheme).Count().ShouldEqual(1);
    [Fact] void should_record_the_marker_for_the_completing_scheme() => _ticketContext.Properties.Items[SessionProvider.MarkerStateKey].ShouldEqual("microsoft");
    [Fact] void should_record_the_completing_scheme() => _ticketContext.Principal.FindFirst(SessionClaims.ProviderScheme).Value.ShouldEqual("microsoft");
}
