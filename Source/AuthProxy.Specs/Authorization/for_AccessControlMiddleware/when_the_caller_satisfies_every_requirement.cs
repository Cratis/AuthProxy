// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware;

/// <summary>
/// A caller who qualifies is forwarded untouched, with nothing written to the response.
/// </summary>
public class when_the_caller_satisfies_every_requirement : given.an_access_control_middleware
{
    void Establish()
    {
        CallerCarrying(new Claim("urn:github:organization", "Cratis"));
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_write_an_error_page() => _errorPageProvider.DidNotReceiveWithAnyArgs().WriteErrorPageAsync(default!, default!, default);
    [Fact] void should_leave_the_status_alone() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}
