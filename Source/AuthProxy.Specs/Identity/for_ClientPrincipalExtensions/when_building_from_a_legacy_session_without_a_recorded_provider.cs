// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// Specifies that a session recording no provider has an empty account provider.
/// </summary>
public class when_building_from_a_legacy_session_without_a_recorded_provider : Specification
{
    ClientPrincipal? _result;

    void Establish()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42")], "AuthenticationTypes.Federation"));
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

    [Fact] void should_have_an_empty_account_provider() => _result.AccountProvider.ShouldEqual(string.Empty);
    [Fact] void should_keep_the_forwarded_identity_provider() => _result.IdentityProvider.ShouldEqual("AuthenticationTypes.Federation");

    sealed class TestAuthenticateResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
