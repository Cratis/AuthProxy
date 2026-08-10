// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.given;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.when_validating_an_enriched_cookie_principal;

/// <summary>
/// Specifies that a fourth claim in the case-insensitive reserved namespace invalidates an enriched cookie principal.
/// </summary>
public class with_an_additional_case_varied_reserved_claim : a_canonical_identity_resolver
{
    CanonicalIdentityResolution _result;

    void Because() => _result = _resolver.Resolve(
        Principal(
            new Claim(CanonicalIdentityClaims.ProviderKey, ProviderKey),
            new Claim(CanonicalIdentityClaims.Issuer, Issuer),
            new Claim(CanonicalIdentityClaims.Subject, "subject-42"),
            new Claim("URN:CRATIS:IDENTITY:UNEXPECTED", "untrusted")),
        CookieAuthenticationDefaults.AuthenticationScheme);

    [Fact] void should_fail_closed() => _result.Succeeded.ShouldBeFalse();
}
