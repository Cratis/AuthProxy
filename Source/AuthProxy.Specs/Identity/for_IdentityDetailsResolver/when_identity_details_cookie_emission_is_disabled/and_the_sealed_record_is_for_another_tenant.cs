// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_details_cookie_emission_is_disabled;

public class and_the_sealed_record_is_for_another_tenant : given.a_resolver_with_legacy_identity_cookies
{
    void Establish() => _context.Request.Headers.Cookie = _bobSealedCookie;

    async Task Because() => _result = await _resolver.Resolve(_context, _bob, OtherTenantId);

    [Fact] void should_ask_the_identity_endpoint() => (_handler.Calls - _callsAfterIssuing).ShouldEqual(1);
    [Fact] void should_not_write_a_readable_identity() => WritesReadableValue(_context).ShouldBeFalse();
}
