// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_reusing_a_sealed_authorization;

public class and_the_tenant_has_changed : given.a_resolver_with_issued_identity_cookies
{
    async Task Establish()
    {
        await IssueIdentityCookies();
        _context.Request.Headers.Cookie = $"{_bobSealedCookie}; {_bobReadableCookie}";
    }

    async Task Because() => _result = await _resolver.Resolve(_context, _bob, OtherTenantId);

    [Fact] void should_ask_the_services_again() => (_handler.Calls - _callsAfterIssuing).ShouldEqual(1);
    [Fact] void should_rewrite_the_readable_cookie_for_the_current_caller() => ReadableCookieIn(_context).ShouldMatch(_ => _.GetProperty("id").GetString() == "user-b" && _.GetProperty("name").GetString() == "Bob");
}
