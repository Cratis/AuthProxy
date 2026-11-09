// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_completing_a_fresh_oidc_authentication : configured_canonical_provider_callbacks
{
    [Theory]
    [InlineData("fresh", true)]
    [InlineData("stale", false)]
    [InlineData("missing", false)]
    [InlineData("malformed", false)]
    [InlineData("future", false)]
    [InlineData("duplicate", false)]
    public async Task should_only_complete_a_marked_callback_with_recent_signed_time(string kind, bool accepted)
    {
        var context = Context();
        var now = FreshAuthenticationChallenge.Now(context);
        var value = now.AddSeconds(kind == "stale" ? -600 : kind == "future" ? 600 : -10).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var claims = new List<Claim>();
        if (kind != "missing") claims.Add(new Claim("auth_time", kind == "malformed" ? "yesterday" : value));
        if (kind == "duplicate") claims.Add(new Claim("auth_time", value));
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "subject-42"), new Claim("auth_time", value)], "microsoft"));
        var properties = new AuthenticationProperties { RedirectUri = "/approve" };
        properties.Items[FreshAuthenticationChallenge.PropertyKey] = "300";
        var scheme = new AuthenticationScheme("microsoft", "microsoft", typeof(OpenIdConnectHandler));
        var token = new TokenValidatedContext(context, scheme, _oidcOptions, principal, properties)
        {
            SecurityToken = new JwtSecurityToken(issuer: ValidatedIssuer, claims: claims)
        };
        await _oidcOptions.Events.OnTokenValidated(token);
        if (!accepted)
        {
            token.Result!.Handled.ShouldBeTrue();
            context.Response.Headers.Location.ToString().ShouldContain("reason=fresh-authentication-required");
            context.Response.Headers.SetCookie.ToString().Contains(".AspNetCore.Cookies=", StringComparison.Ordinal).ShouldBeFalse();
            principal.HasClaim(claim => claim.Type == SessionClaims.AuthenticationTime).ShouldBeFalse();
            return;
        }
        var ticket = TicketContext(context, "microsoft", _oidcOptions, principal, properties);
        await _oidcOptions.Events.OnTicketReceived(ticket);
        SessionAuthenticationTime.TryRead(ticket.Principal!, properties, out var time).ShouldBeTrue();
        time.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture).ShouldEqual(value);
        SessionProvider.TryRead(ticket.Principal!, properties, out _).ShouldBeTrue();
    }

    [Fact]
    public async Task should_request_prompt_and_age_only_for_marked_challenges()
    {
        var context = Context();
        var scheme = new AuthenticationScheme("microsoft", "microsoft", typeof(OpenIdConnectHandler));
        var ordinary = new RedirectContext(context, scheme, _oidcOptions, new AuthenticationProperties()) { ProtocolMessage = new OpenIdConnectMessage() };
        await _oidcOptions.Events.OnRedirectToIdentityProvider(ordinary);
        ordinary.ProtocolMessage.Prompt.ShouldBeNull();
        ordinary.ProtocolMessage.MaxAge.ShouldBeNull();
        var properties = new AuthenticationProperties();
        properties.Items[FreshAuthenticationChallenge.PropertyKey] = "60";
        var marked = new RedirectContext(context, scheme, _oidcOptions, properties) { ProtocolMessage = new OpenIdConnectMessage() };
        await _oidcOptions.Events.OnRedirectToIdentityProvider(marked);
        marked.ProtocolMessage.Prompt.ShouldEqual("login");
        marked.ProtocolMessage.MaxAge.ShouldEqual("60");
    }
}
