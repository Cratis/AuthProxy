// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware;

/// <summary>
/// A path a service declares anonymous is not gated — not for the caller with no session, and not for the
/// one who happens to have one.
/// <para>
/// This is not a loophole so much as the only coherent reading. A declared path exists precisely for
/// callers who have no session — a webhook receiver, a magic-link landing page, a signed-token report —
/// and a caller with no session carries no claims, so any requirement at all would refuse every one of
/// them. A payment provider posting a webhook would get a <c>403</c> it cannot do anything about, and the
/// declaration that was supposed to make the path reachable would have been undone by a setting made
/// somewhere else entirely.
/// </para>
/// <para>
/// The authenticated case is asserted alongside it because the two go through different branches and only
/// one of them is obvious: a signed-in person following a link into a public page must not be refused for
/// lacking membership the page never required.
/// </para>
/// </summary>
public class when_the_path_is_anonymous : given.an_access_control_middleware
{
    bool _anonymousCallerForwarded;
    bool _authenticatedCallerForwarded;

    void Establish()
    {
        _context.Request.Path = AnonymousPath;
        BuildMiddleware();
    }

    async Task Because()
    {
        await _middleware.InvokeAsync(_context);
        _anonymousCallerForwarded = _nextCalled;

        _nextCalled = false;
        CallerCarrying(new Claim("urn:github:organization", "some-other-org"));
        await _middleware.InvokeAsync(_context);
        _authenticatedCallerForwarded = _nextCalled;
    }

    [Fact] void should_forward_a_caller_with_no_session() => _anonymousCallerForwarded.ShouldBeTrue();
    [Fact] void should_forward_a_signed_in_caller_who_would_otherwise_be_refused() => _authenticatedCallerForwarded.ShouldBeTrue();
    [Fact] void should_not_write_an_error_page() => _errorPageProvider.DidNotReceiveWithAnyArgs().WriteErrorPageAsync(default!, default!, default);
}
