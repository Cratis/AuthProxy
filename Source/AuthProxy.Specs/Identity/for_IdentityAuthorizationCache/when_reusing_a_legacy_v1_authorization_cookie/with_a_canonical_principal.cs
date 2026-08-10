// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_reusing_a_legacy_v1_authorization_cookie;

/// <summary>
/// Specifies that a canonical principal never accepts a version-one legacy authorization cookie.
/// </summary>
public class with_a_canonical_principal : a_legacy_v1_authorization_cookie
{
    bool _result;

    void Because() => _result = _cache.IsAuthorized(
        Replay(DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()),
        CanonicalPrincipal(),
        TenantId);

    [Fact] void should_not_be_authorized() => _result.ShouldBeFalse();
}
