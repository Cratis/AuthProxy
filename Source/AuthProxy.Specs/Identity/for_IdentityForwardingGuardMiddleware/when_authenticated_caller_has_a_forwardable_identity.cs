// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Identity.for_IdentityForwardingGuardMiddleware;

public class when_authenticated_caller_has_a_forwardable_identity : given.a_proxied_request
{
    void Establish()
    {
        SetAuthenticatedUser();
        _canonicalIdentityResolver
            .Resolve(Arg.Any<ClaimsPrincipal>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<bool>())
            .Returns(CanonicalIdentityResolution.Legacy(_context.User));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_sign_the_caller_out() => _authenticationService.DidNotReceiveWithAnyArgs().SignOutAsync(default!, default, default);
}
