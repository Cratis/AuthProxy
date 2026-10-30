// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_details_cookie_emission_is_disabled;

public class and_the_result_is_served_from_memory : given.a_resolver_with_legacy_identity_cookies
{
    int _callsAfterPriming;

    async Task Establish()
    {
        _config.Session.IdentityResultCacheDuration = TimeSpan.FromMinutes(1);
        await _resolver.Resolve(new DefaultHttpContext(), _bob, TenantId);
        _callsAfterPriming = _handler.Calls;
        _context.Request.Headers.Cookie = $"{Cookies.Identity}={BobReadableValue}";
    }

    async Task Because() => _result = await _resolver.Resolve(_context, _bob, TenantId);

    [Fact] void should_not_ask_the_identity_endpoint_again() => (_handler.Calls - _callsAfterPriming).ShouldEqual(0);
    [Fact] void should_record_the_sealed_authorization() => WritesSealedRecord(_context).ShouldBeTrue();
    [Fact] void should_not_write_a_readable_identity() => WritesReadableValue(_context).ShouldBeFalse();
    [Fact] void should_expire_the_legacy_readable_cookie() => ExpiresReadableCookie(_context).ShouldBeTrue();
}
