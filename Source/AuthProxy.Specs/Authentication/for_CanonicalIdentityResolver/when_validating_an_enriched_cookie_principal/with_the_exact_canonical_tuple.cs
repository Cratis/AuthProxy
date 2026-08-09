// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.given;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.when_validating_an_enriched_cookie_principal;

/// <summary>
/// Specifies that an enriched cookie principal containing exactly one valid canonical tuple is accepted.
/// </summary>
public class with_the_exact_canonical_tuple : a_canonical_identity_resolver
{
    CanonicalIdentityResolution _result;

    void Because() => _result = _resolver.Resolve(
        Principal(
            new Claim(CanonicalIdentityClaims.ProviderKey, ProviderKey),
            new Claim(CanonicalIdentityClaims.Issuer, Issuer),
            new Claim(CanonicalIdentityClaims.Subject, "subject-42")),
        CookieAuthenticationDefaults.AuthenticationScheme);

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
