// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_binding_the_invite_to_the_invited_email;

public class and_the_invite_targets_no_email : given.an_invite_exchange
{
    void Establish()
    {
        // Backward compatibility: an invite that carries no email claim has nothing to bind against.
        GivenAuthenticatedUserWith(new Claim("email", "anyone@example.com"), new Claim("email_verified", "true"));
        GivenPendingInviteCookie(CreateSignedToken());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeTrue();
    [Fact] void should_continue_the_pipeline() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_serve_an_error_page() =>
        _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
}
