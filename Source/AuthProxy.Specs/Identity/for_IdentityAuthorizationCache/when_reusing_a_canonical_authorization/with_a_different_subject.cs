// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_reusing_a_canonical_authorization;

/// <summary>
/// Specifies that a different canonical subject cannot reuse another subject's authorization.
/// </summary>
public class with_a_different_subject : a_recorded_canonical_authorization
{
    bool _result;

    void Because() => _result = _cache.IsAuthorized(_replayContext, CanonicalPrincipal(ProviderKey, Issuer, "different-subject"), TenantId);

    [Fact] void should_not_be_authorized() => _result.ShouldBeFalse();
}
