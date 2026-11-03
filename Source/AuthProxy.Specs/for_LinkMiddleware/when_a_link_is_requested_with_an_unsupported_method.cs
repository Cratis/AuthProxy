// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_a_link_is_requested_with_an_unsupported_method : given.a_link_page_context
{
    void Establish()
    {
        _context.Request.Method = HttpMethods.Put;
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create("token", "the-link-token");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_challenge() => _authenticationService.DidNotReceiveWithAnyArgs().ChallengeAsync(default!, default, default);
    [Fact] void should_answer_method_not_allowed() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status405MethodNotAllowed);
    [Fact] void should_name_the_allowed_methods() => _context.Response.Headers.Allow.ToString().ShouldEqual("GET, POST");
}
