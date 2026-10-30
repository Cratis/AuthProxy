// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_details_cookie_emission_is_disabled;

public class and_the_identity_is_resolved_afresh : given.a_resolver_with_legacy_identity_cookies
{
    async Task Because() => _result = await _resolver.Resolve(_context, _bob, TenantId);

    [Fact] void should_ask_the_identity_endpoint() => (_handler.Calls - _callsAfterIssuing).ShouldEqual(1);
    [Fact] void should_admit_the_caller() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_record_the_sealed_authorization() => WritesSealedRecord(_context).ShouldBeTrue();
    [Fact] void should_not_write_a_readable_identity() => WritesReadableValue(_context).ShouldBeFalse();
}
