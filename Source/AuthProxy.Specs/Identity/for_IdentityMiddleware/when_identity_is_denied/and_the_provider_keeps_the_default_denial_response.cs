// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

/// <summary>
/// A provider that did not opt in keeps today's forbidden page and today's session handling.
/// </summary>
public class and_the_provider_keeps_the_default_denial_response : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        SignedInThroughProvider(C.OidcDenialResponse.Forbidden);
        DenyIdentity();
        Navigate();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_with_the_forbidden_page() => ShouldHaveBeenRefused();
    [Fact] void should_preserve_the_session() => ShouldHavePreservedSession();
    [Fact] void should_not_redirect() => _context.Response.Headers.Location.ToString().ShouldBeEmpty();
}
