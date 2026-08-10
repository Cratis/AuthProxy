// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware;

/// <summary>
/// With nothing declared the middleware is a pass-through, which is what makes this a safe upgrade.
/// <para>
/// Every AuthProxy deployment that exists today declares nothing, and the middleware is now in all of
/// their pipelines. Any behavior at all here — a refusal, a header, a changed status — would be a change
/// they never asked for, delivered by a version bump.
/// </para>
/// </summary>
public class when_no_authorization_is_configured : given.an_access_control_middleware
{
    void Establish()
    {
        _config.Authorization = new C.Authorization();
        CallerCarrying(new Claim(ClaimTypes.NameIdentifier, "anyone-at-all"));
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_write_an_error_page() => _errorPageProvider.DidNotReceiveWithAnyArgs().WriteErrorPageAsync(default!, default!, default);
    [Fact] void should_leave_the_status_alone() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}
