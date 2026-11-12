// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

/// <summary>
/// An allowed identity is forwarded untouched, whatever the provider's denial response.
/// </summary>
public class and_the_provider_answers_denials_like_a_failed_sign_in_and_nobody_is_denied : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        SignedInThroughProvider(C.OidcDenialResponse.FailedSignIn);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_preserve_the_session() => ShouldHavePreservedSession();
}
