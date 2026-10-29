// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_reusing_a_sealed_authorization;

public class and_there_is_no_readable_cookie : given.a_resolver_with_issued_identity_cookies
{
    async Task Establish()
    {
        await IssueIdentityCookies();
        _context.Request.Headers.Cookie = _bobSealedCookie;
    }

    async Task Because() => _result = await _resolver.Resolve(_context, _bob, TenantId);

    [Fact] void should_reuse_the_sealed_record() => (_handler.Calls - _callsAfterIssuing).ShouldEqual(0);
    [Fact] void should_not_write_a_readable_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain($"{Cookies.Identity}=");
}
