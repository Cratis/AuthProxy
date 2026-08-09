// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache;

/// <summary>
/// Specifies the released tenant and user identifier reuse behavior for legacy principals.
/// </summary>
public class when_reusing_a_legacy_authorization : a_recorded_canonical_authorization
{
    bool _result;

    void Because()
    {
        var recorded = new ClientPrincipal { IdentityProvider = "legacy-a", UserId = Subject };
        var presented = new ClientPrincipal { IdentityProvider = "legacy-b", UserId = Subject };
        var context = Record(recorded, TenantId);
        _result = _cache.IsAuthorized(context, presented, TenantId);
    }

    [Fact] void should_be_authorized() => _result.ShouldBeTrue();
}
