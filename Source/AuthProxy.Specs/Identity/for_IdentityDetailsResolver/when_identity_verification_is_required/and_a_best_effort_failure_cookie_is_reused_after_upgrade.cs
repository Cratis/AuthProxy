// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

public class and_a_best_effort_failure_cookie_is_reused_after_upgrade : given.an_upgrading_verification_resolver
{
    async Task Establish()
    {
        _handler.Respond = (_, _, _) => throw new HttpRequestException("endpoint unavailable");
        await IssueCookieAndUpgrade(C.IdentityVerificationMode.BestEffort);
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_have_admitted_the_enrichment_only_request() => _previousResult.IsAuthorized.ShouldBeTrue();
    [Fact] void should_check_the_endpoint_again() => _handler.Calls.ShouldEqual(2);
    [Fact] void should_deny_the_unverified_caller() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_return_forbidden() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
}
