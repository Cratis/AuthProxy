// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_reusing_a_sealed_authorization;

public class and_the_readable_cookie_names_the_same_user : given.a_resolver_with_issued_identity_cookies
{
    async Task Establish()
    {
        await IssueIdentityCookies();
        _context.Request.Headers.Cookie = $"{_bobSealedCookie}; {_bobReadableCookie}";
    }

    async Task Because() => _result = await _resolver.Resolve(_context, _bob, TenantId);

    [Fact] void should_reuse_the_sealed_record() => (_handler.Calls - _callsAfterIssuing).ShouldEqual(0);
    [Fact] void should_leave_the_readable_cookie_alone() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain($"{Cookies.Identity}=");
    [Fact] void should_authorize_the_caller() => _result.IsAuthorized.ShouldBeTrue();
}
