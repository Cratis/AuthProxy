// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver;

public class when_two_providers_assert_the_same_raw_subject : a_canonical_identity_resolver
{
    CanonicalIdentityResolution _first;
    CanonicalIdentityResolution _second;

    protected override C.AuthProxy CreateConfiguration()
    {
        var configuration = base.CreateConfiguration();
        configuration.Authentication.OAuthProviders.Add(new C.OAuthProvider
        {
            Name = "GitHub",
            CanonicalIdentity = new C.CanonicalIdentity
            {
                ProviderKey = "github-enterprise",
                SubjectClaimType = "id",
                Issuer = "https://github.example.com/"
            }
        });
        return configuration;
    }

    void Because()
    {
        _first = _resolver.Resolve(Principal(new Claim("oid", "same-subject")), Scheme, Issuer);
        _second = _resolver.Resolve(
            new ClaimsPrincipal(new ClaimsIdentity([new Claim("id", "same-subject")], "github")),
            "github");
    }

    [Fact] void should_resolve_both() => (_first.Succeeded && _second.Succeeded).ShouldBeTrue();
    [Fact] void should_keep_the_provider_accounts_distinct() => _first.Identity!.ProviderKey.ShouldNotEqual(_second.Identity!.ProviderKey);
    [Fact] void should_normalize_the_explicit_oauth_issuer() => _second.Identity!.NormalizedIssuer.ShouldEqual("https://github.example.com");
}
