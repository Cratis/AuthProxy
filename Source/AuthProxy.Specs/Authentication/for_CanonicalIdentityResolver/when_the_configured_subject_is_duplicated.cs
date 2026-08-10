// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver;

public class when_the_configured_subject_is_duplicated : a_canonical_identity_resolver
{
    CanonicalIdentityResolution _result;

    void Because() => _result = _resolver.Resolve(
        Principal(
            new Claim("oid", "first"),
            new Claim("oid", "second")),
        Scheme,
        Issuer);

    [Fact] void should_fail_closed() => _result.Succeeded.ShouldBeFalse();
}
