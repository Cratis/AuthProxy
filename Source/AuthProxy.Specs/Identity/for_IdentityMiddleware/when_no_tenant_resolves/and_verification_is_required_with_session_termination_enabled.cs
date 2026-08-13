// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_no_tenant_resolves;

public class and_verification_is_required_with_session_termination_enabled : given.an_identity_middleware
{
    void Establish() => EnableSessionTermination();

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_terminate_the_session() => ShouldHaveTerminatedSession();
    [Fact] void should_still_refuse_the_request() => ShouldHaveBeenRefused();
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_pretend_to_have_asked() =>
        _resolver.DidNotReceive().Resolve(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>());
}
