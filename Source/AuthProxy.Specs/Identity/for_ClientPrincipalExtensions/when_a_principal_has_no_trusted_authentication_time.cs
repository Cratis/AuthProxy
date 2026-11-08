// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.OnBehalfSessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// Specifies that an auth_time is never forwarded unless AuthProxy recorded it for a session: a provider's own value,
/// a mismatched marker, a bearer principal and an on-behalf principal all carry none.
/// </summary>
public class when_a_principal_has_no_trusted_authentication_time : Specification
{
    [Theory]
    [InlineData("provider-only")]
    [InlineData("marker-mismatch")]
    [InlineData("bearer")]
    [InlineData("on-behalf")]
    public void should_forward_no_auth_time_claim(string kind)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42"), new Claim("auth_time", "1700000000")], kind == "bearer" ? "Bearer" : "AuthenticationTypes.Federation"));
        var properties = new AuthenticationProperties();
        if (string.Equals(kind, "marker-mismatch", StringComparison.Ordinal) || string.Equals(kind, "on-behalf", StringComparison.Ordinal))
        {
            SessionAuthenticationTime.Stamp(principal, properties, DateTimeOffset.FromUnixTimeSeconds(1700000000));
        }
        if (kind == "marker-mismatch")
        {
            properties.Items[SessionAuthenticationTime.PropertyKey] = "1700000001";
        }
        var context = new DefaultHttpContext { RequestServices = new ServiceCollection().BuildServiceProvider(), User = principal };
        var scheme = kind == "bearer" ? "Bearer" : CookieAuthenticationDefaults.AuthenticationScheme;
        context.Features.Set<IAuthenticateResultFeature>(new TestAuthenticateResultFeature(AuthenticateResult.Success(new AuthenticationTicket(principal, properties, scheme))));
        if (kind == "on-behalf")
        {
            var represented = new ClientPrincipal { IdentityProvider = "application", UserId = "represented", UserDetails = "Represented", UserRoles = [], Claims = [] };
            context.SetOnBehalf(new OnBehalfContext(null!, represented, string.Empty, null!));
        }

        var result = context.BuildClientPrincipal();

        result!.Claims.Any(_ => string.Equals(_.Type, "auth_time", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
    }

    sealed class TestAuthenticateResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
