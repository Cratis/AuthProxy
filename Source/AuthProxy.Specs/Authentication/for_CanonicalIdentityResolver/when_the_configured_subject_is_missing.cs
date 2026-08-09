// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver.given;

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityResolver;

public class when_the_configured_subject_is_missing : a_canonical_identity_resolver
{
    CanonicalIdentityResolution _result;

    void Because() => _result = _resolver.Resolve(
        Principal(
            new Claim("sub", "pairwise-subject"),
            new Claim("email", "person@example.com")),
        Scheme,
        Issuer);

    [Fact] void should_fail_closed() => _result.Succeeded.ShouldBeFalse();
    [Fact] void should_not_fall_back_to_an_email_or_subject() => _result.Identity.ShouldBeNull();
}
