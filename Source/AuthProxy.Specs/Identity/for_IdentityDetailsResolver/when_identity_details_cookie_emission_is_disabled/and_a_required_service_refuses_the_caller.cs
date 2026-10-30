// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_details_cookie_emission_is_disabled;

public class and_a_required_service_refuses_the_caller : given.a_resolver_with_legacy_identity_cookies
{
    void Establish()
    {
        _service.IdentityVerification = C.IdentityVerificationMode.Required;
        _handler.Respond = (_, _, _) => Task.FromResult(Response(System.Net.HttpStatusCode.OK, NegativeBody));
        CarryReadableCookie(BobReadableValue);
    }

    async Task Because() => _result = await _resolver.Resolve(_context, _bob, TenantId);

    [Fact] void should_refuse_the_caller() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_serve_the_forbidden_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_not_write_a_readable_identity() => WritesReadableValue(_context).ShouldBeFalse();
}
