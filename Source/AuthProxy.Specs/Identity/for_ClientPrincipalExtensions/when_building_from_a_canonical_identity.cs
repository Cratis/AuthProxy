// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

public class when_building_from_a_canonical_identity : Specification
{
    const string Subject = "entra-object-id";
    DefaultHttpContext _context;
    ClientPrincipal? _result;

    void Establish()
    {
        var configuration = new C.AuthProxy
        {
            Authentication = new C.Authentication
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
            }
        };
        var options = Substitute.For<IOptionsMonitor<C.Authentication>>();
        options.CurrentValue.Returns(configuration.Authentication);
        var resolver = new CanonicalIdentityResolver(options);
        var enriched = resolver.Resolve(
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("oid", Subject),
                new Claim("sub", "different-pairwise-subject"),
                new Claim("name", "Cosmetic Name")
            ],
            "microsoft-entra")),
            "microsoft-entra",
            "https://identity.example.com/");

        var services = new ServiceCollection()
            .AddSingleton<ICanonicalIdentityResolver>(resolver)
            .BuildServiceProvider();

        _context = new DefaultHttpContext
        {
            RequestServices = services,
            User = enriched.Principal!
        };
    }

    void Because()
    {
        _result = _context.BuildClientPrincipal();
        _context.Request.SetMicrosoftIdentityHeaders(_result!);
    }

    [Fact] void should_use_the_canonical_subject_as_user_id() => _result!.UserId.ShouldEqual(Subject);
    [Fact] void should_use_the_canonical_subject_as_the_principal_id_header() => _context.Request.Headers[Headers.PrincipalId].ToString().ShouldEqual(Subject);
    [Fact] void should_forward_the_same_reserved_subject() => _result!.Claims.Single(_ => _.Type == CanonicalIdentityClaims.Subject).Value.ShouldEqual(Subject);
    [Fact] void should_forward_the_stable_provider_key() => _result!.Claims.Single(_ => _.Type == CanonicalIdentityClaims.ProviderKey).Value.ShouldEqual("workforce");
    [Fact] void should_forward_the_normalized_issuer() => _result!.Claims.Single(_ => _.Type == CanonicalIdentityClaims.Issuer).Value.ShouldEqual("https://identity.example.com");
    [Fact] void should_keep_the_identity_provider_property_compatible() => _result!.IdentityProvider.ShouldEqual("workforce");
}
