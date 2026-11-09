// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// Specifies that the authentication time AuthProxy recorded is forwarded as the only auth_time claim, in Unix seconds.
/// </summary>
public class when_building_from_a_session_with_a_recorded_authentication_time : Specification
{
    DefaultHttpContext _context;
    ClientPrincipal? _result;

    void Establish()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42"), new Claim("auth_time", "1"), new Claim("AUTH_TIME", "2")], "AuthenticationTypes.Federation"));
        var properties = new AuthenticationProperties();
        SessionProvider.Stamp(principal, properties, "microsoft");
        SessionAuthenticationTime.Stamp(principal, properties, DateTimeOffset.FromUnixTimeSeconds(1700000000));
        _context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().BuildServiceProvider(),
            User = principal
        };
        _context.Features.Set<IAuthenticateResultFeature>(new TestAuthenticateResultFeature(
            AuthenticateResult.Success(new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme))));
    }

    void Because() => _result = _context.BuildClientPrincipal();

    [Fact] void should_forward_exactly_one_auth_time_claim() => _result!.Claims.Count(_ => string.Equals(_.Type, "auth_time", StringComparison.OrdinalIgnoreCase)).ShouldEqual(1);
    [Fact] void should_forward_the_recorded_time_in_unix_seconds() => _result!.Claims.Single(_ => _.Type == "auth_time").Value.ShouldEqual("1700000000");
    [Fact] void should_not_forward_the_reserved_session_claim() => _result!.Claims.Any(_ => SessionClaims.IsReserved(_.Type)).ShouldBeFalse();
    [Fact] void should_keep_the_other_claims() => _result!.Claims.Any(_ => _.Type == "sub").ShouldBeTrue();

    sealed class TestAuthenticateResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
