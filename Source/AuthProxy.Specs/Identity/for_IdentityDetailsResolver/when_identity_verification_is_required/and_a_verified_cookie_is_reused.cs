// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

public class and_a_verified_cookie_is_reused : given.an_upgrading_verification_resolver
{
    async Task Establish() => await IssueCookieAndUpgrade(C.IdentityVerificationMode.Required);

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_reuse_the_verified_record() => _handler.Calls.ShouldEqual(1);
    [Fact] void should_admit_the_verified_caller() => _result.IsAuthorized.ShouldBeTrue();
}
