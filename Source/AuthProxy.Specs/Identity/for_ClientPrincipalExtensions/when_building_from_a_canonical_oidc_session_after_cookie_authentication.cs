// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// The production shape of every canonical OIDC session: the token-validated identity carries
/// "AuthenticationTypes.Federation" as its authentication type — never the provider scheme — and the
/// request was authenticated by the cookie handler, recorded in the authenticate-result feature. Building
/// the client principal must resolve against the scheme that authenticated the request, not the identity's
/// authentication type; getting that wrong made every proxied request go out without identity headers
/// while the session itself stayed valid.
/// </summary>
public class when_building_from_a_canonical_oidc_session_after_cookie_authentication : Specification
{
    const string Subject = "entra-object-id";
    DefaultHttpContext _context;
    ClientPrincipal? _result;

    void Establish()
    {
        var configuration = new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider
                {
                    Name = "Microsoft Entra",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = "workforce",
                        SubjectClaimType = "oid"
                    }
                }
            ]
        };
        var options = Substitute.For<IOptionsMonitor<C.Authentication>>();
        options.CurrentValue.Returns(configuration);
        var resolver = new CanonicalIdentityResolver(options);

        // The fresh callback enriches the principal under the provider scheme, exactly as the real ticket
        // handler does — but the identity itself carries the federation authentication type the OIDC token
        // validation stamps on it.
        var enriched = resolver.Resolve(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("oid", Subject),
                new Claim("name", "Cosmetic Name")
            ],
            "AuthenticationTypes.Federation")),
            "microsoft-entra",
            "https://identity.example.com/",
            isFreshAuthentication: true);

        var services = new ServiceCollection()
            .AddSingleton<ICanonicalIdentityResolver>(resolver)
            .BuildServiceProvider();

        _context = new DefaultHttpContext
        {
            RequestServices = services,
            User = enriched.Principal!
        };

        // On a later request the cookie handler authenticates and the framework records the winning scheme.
        _context.Features.Set<IAuthenticateResultFeature>(new TestAuthenticateResultFeature(
            AuthenticateResult.Success(new AuthenticationTicket(
                enriched.Principal!,
                CookieAuthenticationDefaults.AuthenticationScheme))));
    }

    void Because() => _result = _context.BuildClientPrincipal();

    [Fact] void should_build_a_principal() => _result.ShouldNotBeNull();
    [Fact] void should_use_the_canonical_subject_as_user_id() => _result!.UserId.ShouldEqual(Subject);
    [Fact] void should_keep_the_stable_provider_key() => _result!.IdentityProvider.ShouldEqual("workforce");

    sealed class TestAuthenticateResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
