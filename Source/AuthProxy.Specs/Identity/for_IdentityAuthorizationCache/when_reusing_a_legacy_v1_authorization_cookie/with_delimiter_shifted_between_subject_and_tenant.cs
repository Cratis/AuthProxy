// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_reusing_a_legacy_v1_authorization_cookie;

/// <summary>
/// Specifies that a sealed version-one payload cannot move a delimiter-bearing subject suffix into the presented tenant.
/// </summary>
public class with_delimiter_shifted_between_subject_and_tenant : a_legacy_v1_authorization_cookie
{
    bool _result;

    void Because() => _result = _cache.IsAuthorized(
        Replay(
            DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),
            "victim|tenant-b",
            "tenant-a"),
        LegacyPrincipal("victim"),
        "tenant-b|tenant-a");

    [Fact] void should_not_be_authorized() => _result.ShouldBeFalse();
}
