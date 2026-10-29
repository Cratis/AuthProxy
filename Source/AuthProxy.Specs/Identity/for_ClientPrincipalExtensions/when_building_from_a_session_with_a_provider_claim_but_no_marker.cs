// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// Specifies that a provider claim without the marker is not trusted as the account provider.
/// </summary>
public class when_building_from_a_session_with_a_provider_claim_but_no_marker : Specification
{
    ClientPrincipal? _result;

    void Establish()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42"), new Claim(SessionClaims.ProviderScheme, "microsoft")], "AuthenticationTypes.Federation"));
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().BuildServiceProvider(),
            User = principal
        };
        context.Features.Set<IAuthenticateResultFeature>(new TestAuthenticateResultFeature(
            AuthenticateResult.Success(new AuthenticationTicket(principal, CookieAuthenticationDefaults.AuthenticationScheme))));
        _context = context;
    }

    DefaultHttpContext _context;

    void Because() => _result = _context.BuildClientPrincipal();

    [Fact] void should_not_trust_the_claim() => _result.AccountProvider.ShouldEqual(string.Empty);
    [Fact] void should_keep_the_forwarded_identity_provider() => _result.IdentityProvider.ShouldEqual("AuthenticationTypes.Federation");
    [Fact] void should_not_forward_the_session_claim() => _result.Claims.Any(_ => SessionClaims.IsReserved(_.Type)).ShouldBeFalse();

    sealed class TestAuthenticateResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
