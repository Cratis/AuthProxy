// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache;

/// <summary>
/// Specifies that a legacy authorization recorded for one identity provider is not reused for the same user identifier from another provider.
/// </summary>
public class when_reusing_a_legacy_authorization_from_another_provider : a_recorded_canonical_authorization
{
    bool _result;

    void Because()
    {
        var recorded = new ClientPrincipal { IdentityProvider = "legacy-a", UserId = Subject };
        var presented = new ClientPrincipal { IdentityProvider = "legacy-b", UserId = Subject };
        var context = Record(recorded, TenantId);
        _result = _cache.IsAuthorized(context, presented, TenantId);
    }

    [Fact] void should_not_be_authorized() => _result.ShouldBeFalse();
}
