// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

public class and_session_termination_is_disabled : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        _config.Session.TerminateOnIdentityDenial = false;
        _resolver
            .Resolve(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>())
            .Returns(_ => new IdentityProviderResult("user-1", "User One", true, false, [], new object()));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_preserve_the_session() => ShouldHavePreservedSession();
    [Fact] void should_still_refuse_the_request() => ShouldHaveBeenRefused();
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
}
