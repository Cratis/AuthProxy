// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

public class and_a_cached_best_effort_result_exists_after_reload : given.an_upgrading_verification_resolver
{
    async Task Establish()
    {
        _config.Session.IdentityResultCacheDuration = TimeSpan.FromMinutes(1);
        _handler.Respond = (_, _, _) => throw new HttpRequestException("connection refused");
        await IssueCookieAndUpgrade(C.IdentityVerificationMode.BestEffort);

        // Exercise the result cache rather than the cookie path on the request after reload.
        _context.Request.Headers.Cookie = string.Empty;
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_have_admitted_the_best_effort_failure() => _previousResult.IsAuthorized.ShouldBeTrue();
    [Fact] void should_verify_again_after_required_is_enabled() => _handler.Calls.ShouldEqual(2);
    [Fact] void should_deny_the_unverified_caller() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_not_seal_the_cached_best_effort_admission() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain("max-age=600");
}
