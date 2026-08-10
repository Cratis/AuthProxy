// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies raw OIDC role preservation from the validated callback through the forwarded client principal.
/// </summary>
public class when_a_configured_oidc_callback_forwards_raw_roles_to_the_client_principal : configured_canonical_provider_callbacks
{
    ClientPrincipal? _clientPrincipal;

    async Task Because()
    {
        var context = Context();
        var properties = new AuthenticationProperties();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("oid", "subject-42"),
            new Claim("role", "raw-role"),
            new Claim("roles", "raw-roles"),
            new Claim(ClaimTypes.Role, "mapped-role"),
            new Claim("Role", "case-varied-role"),
            new Claim("unrelated_role", "unrelated-role")
        ],
        "microsoft"));
        var scheme = new AuthenticationScheme("microsoft", "microsoft", typeof(OpenIdConnectHandler));
        var tokenContext = new TokenValidatedContext(context, scheme, _oidcOptions, principal, properties)
        {
            SecurityToken = new JwtSecurityToken(issuer: ValidatedIssuer)
        };
        await _oidcOptions.Events.OnTokenValidated(tokenContext);
        var ticketContext = TicketContext(context, "microsoft", _oidcOptions, principal, properties);
        await _oidcOptions.Events.OnTicketReceived(ticketContext);
        context.User = ticketContext.Principal!;

        _clientPrincipal = context.BuildClientPrincipal();
    }

    [Fact] void should_preserve_only_the_exact_supported_role_claim_types() =>
        _clientPrincipal!.UserRoles.ShouldContainOnly("raw-role", "raw-roles", "mapped-role", "anonymous", "authenticated");
}
