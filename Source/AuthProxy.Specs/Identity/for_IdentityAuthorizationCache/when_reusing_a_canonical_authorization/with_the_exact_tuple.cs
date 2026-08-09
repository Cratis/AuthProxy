// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_reusing_a_canonical_authorization;

/// <summary>
/// Specifies that the exact canonical tuple can reuse its recorded authorization.
/// </summary>
public class with_the_exact_tuple : a_recorded_canonical_authorization
{
    bool _result;

    void Because() => _result = _cache.IsAuthorized(_replayContext, CanonicalPrincipal(ProviderKey, Issuer, Subject), TenantId);

    [Fact] void should_be_authorized() => _result.ShouldBeTrue();
}
