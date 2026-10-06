// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication;

static class CanonicalOidcFixture
{
    internal static C.Authentication Configuration() => new()
    {
        OidcProviders =
        [
            new C.OidcProvider
            {
                Name = "Workforce",
                CanonicalIdentity = new C.CanonicalIdentity { ProviderKey = "workforce", SubjectClaimType = "oid" },
            }
        ]
    };

    internal static CanonicalIdentityResolver Resolver(C.Authentication configuration)
    {
        var options = Substitute.For<IOptionsMonitor<C.Authentication>>();
        options.CurrentValue.Returns(configuration);
        return new(options);
    }

    internal static ClaimsPrincipal Principal() => Resolver(Configuration()).Resolve(
        new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "configured-subject"), new Claim("sub", "old-sub")], "AuthenticationTypes.Federation")),
        "workforce",
        "https://identity.example.com/",
        isFreshAuthentication: true).Principal!;

    internal static void AuthenticateCookie(HttpContext context, ClaimsPrincipal principal)
    {
        var properties = context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult?.Properties ?? new AuthenticationProperties();
        context.Features.Set<IAuthenticateResultFeature>(new ResultFeature(AuthenticateResult.Success(new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme))));
    }

    sealed class ResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
