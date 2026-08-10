// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.given;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_reusing_a_canonical_authorization;

/// <summary>
/// Specifies that legal delimiter-bearing identity values round-trip without changing tuple boundaries.
/// </summary>
public class with_delimiter_bearing_values : a_recorded_canonical_authorization
{
    const string DelimiterBearingProvider = "workforce|europe";
    const string DelimiterBearingIssuer = "https://identity.example.com/accounts%7Ceurope";
    const string DelimiterBearingSubject = "directory|subject|42";
    bool _result;

    void Because()
    {
        var principal = CanonicalPrincipal(DelimiterBearingProvider, DelimiterBearingIssuer, DelimiterBearingSubject);
        var context = Record(principal, TenantId);
        _result = _cache.IsAuthorized(context, principal, TenantId);
    }

    [Fact] void should_be_authorized() => _result.ShouldBeTrue();
}
