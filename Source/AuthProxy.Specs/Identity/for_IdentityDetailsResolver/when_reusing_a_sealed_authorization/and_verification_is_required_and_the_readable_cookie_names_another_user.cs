// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_reusing_a_sealed_authorization;

public class and_verification_is_required_and_the_readable_cookie_names_another_user : given.a_resolver_with_issued_identity_cookies
{
    async Task Establish()
    {
        _service.IdentityVerification = C.IdentityVerificationMode.Required;
        _config.Session.IdentityRevalidationInterval = TimeSpan.FromMinutes(5);
        await IssueIdentityCookies();
        _context.Request.Headers.Cookie = $"{_bobSealedCookie}; {_aliceReadableCookie}";
    }

    async Task Because() => _result = await _resolver.Resolve(_context, _bob, TenantId);

    [Fact] void should_ask_the_required_service_again() => (_handler.Calls - _callsAfterIssuing).ShouldEqual(1);

    [Fact]
    void should_seal_the_new_verification()
    {
        var nextRequest = new DefaultHttpContext();
        nextRequest.Request.Headers.Cookie = _context.Response.Headers.SetCookie.Single(_ => _.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal)).Split(';', 2)[0];
        _authorizationCache.IsAuthorized(nextRequest, _bob, TenantId).ShouldBeTrue();
    }
}
