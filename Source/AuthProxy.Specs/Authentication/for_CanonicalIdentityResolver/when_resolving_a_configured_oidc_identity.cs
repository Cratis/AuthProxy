// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver;

public class when_resolving_a_configured_oidc_identity : a_canonical_identity_resolver
{
    CanonicalIdentityResolution _result;

    void Because() => _result = _resolver.Resolve(
        Principal(
            new Claim("oid", "configured-object-id"),
            new Claim("sub", "different-pairwise-subject"),
            new Claim(CanonicalIdentityClaims.ProviderKey.ToUpperInvariant(), "hostile-provider"),
            new Claim(CanonicalIdentityClaims.Subject, "hostile-subject")),
        Scheme,
        $"{Issuer}/");

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
    [Fact] void should_select_only_the_configured_subject() => _result.Identity!.Subject.ShouldEqual("configured-object-id");
    [Fact] void should_use_the_stable_provider_key() => _result.Identity!.ProviderKey.ShouldEqual(ProviderKey);
    [Fact] void should_normalize_the_validated_issuer() => _result.Identity!.NormalizedIssuer.ShouldEqual(Issuer);
    [Fact] void should_remove_case_varied_reserved_collisions() => _result.Principal!.Claims.Count(_ => string.Equals(_.Type, CanonicalIdentityClaims.ProviderKey, StringComparison.OrdinalIgnoreCase)).ShouldEqual(1);
    [Fact] void should_overwrite_the_reserved_subject() => _result.Principal!.FindFirst(CanonicalIdentityClaims.Subject)!.Value.ShouldEqual("configured-object-id");
}
