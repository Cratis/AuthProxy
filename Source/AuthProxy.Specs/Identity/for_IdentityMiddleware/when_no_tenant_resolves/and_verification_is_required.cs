// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_no_tenant_resolves;

/// <summary>
/// The guarantee the whole fail-closed mode rests on, at the one place it can be lost. Identity resolution
/// is keyed by principal and tenant, so the middleware only asked for a verdict when a tenant had resolved —
/// a condition that was written while the call was enrichment only, and that nothing revisited when the call
/// became an authorization decision. Every route that reaches this middleware without a tenant therefore
/// skipped the decision and forwarded the caller: a deployment with no tenant resolution configured, a
/// declared anonymous path, a pending-invite cookie on an ordinary path.
/// <para>
/// Skipping a decision is not the same as making one. A deployment that asked to have callers verified gets
/// them refused when nobody could be asked, including when the reason nobody could be asked is the proxy's
/// own configuration.
/// </para>
/// </summary>
public class and_verification_is_required : given.an_identity_middleware
{
    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => ShouldHaveBeenRefused();
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_preserve_the_session_by_default() => ShouldHavePreservedSession();
    [Fact] void should_not_pretend_to_have_asked() =>
        _resolver.DidNotReceive().Resolve(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>());
}
