// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware;

/// <summary>
/// The positive control for the refusal above: the ordinary path still asks, and an admitted caller is still
/// forwarded. A fence that refuses everything would satisfy the fail-closed specs and nothing else.
/// </summary>
public class when_a_tenant_resolves : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        EnableSessionTermination();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_ask_for_a_verdict() =>
        _resolver.Received(1).Resolve(_context, Arg.Any<ClientPrincipal>(), TenantId);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_preserve_the_session() => ShouldHavePreservedSession();
    [Fact] void should_not_refuse_it() =>
        _errorPages.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
}
