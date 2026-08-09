// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authorization.for_AccessControlMiddleware;

/// <summary>
/// A caller with no session is left to the machinery that already refuses them.
/// <para>
/// Refusing them here instead would replace a sign-in with a dead end: <c>SelectProviderMiddleware</c>
/// answers an unauthenticated browser with the provider chooser or a challenge, and the
/// not-authorized page offers only signing out — of a session that does not exist. This gate is about who
/// a signed-in caller <em>is</em>, not about whether there is one.
/// </para>
/// </summary>
public class when_the_caller_has_no_session : given.an_access_control_middleware
{
    void Establish() => BuildMiddleware();

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_leave_the_request_to_the_rest_of_the_pipeline() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_write_an_error_page() => _errorPageProvider.DidNotReceiveWithAnyArgs().WriteErrorPageAsync(default!, default!, default);
}
