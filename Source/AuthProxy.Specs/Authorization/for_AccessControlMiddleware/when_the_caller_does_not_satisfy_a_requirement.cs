// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware;

/// <summary>
/// A signed-in caller who does not qualify is answered with the not-authorized page and goes no further.
/// <para>
/// Two properties, and both matter. The request must not continue — everything downstream is tenancy,
/// identity resolution against a backend, and the reverse proxy, so continuing would mean the very caller
/// being refused had already caused a call into the application. And the answer must be a page at
/// <c>403</c> rather than a redirect: the caller <em>is</em> authenticated, so sending them back to the
/// identity provider signs them in again as the same person and loops forever. <c>403</c> is also a status
/// a non-browser client can act on, so one answer serves both.
/// </para>
/// </summary>
public class when_the_caller_does_not_satisfy_a_requirement : given.an_access_control_middleware
{
    void Establish()
    {
        CallerCarrying(new Claim("urn:github:organization", "some-other-org"));
        BuildMiddleware();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();

    [Fact]
    void should_serve_the_not_authorized_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.NotAuthorized, StatusCodes.Status403Forbidden);
}
