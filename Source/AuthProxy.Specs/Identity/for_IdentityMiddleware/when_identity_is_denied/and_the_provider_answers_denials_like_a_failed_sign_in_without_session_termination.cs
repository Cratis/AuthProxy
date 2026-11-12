// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

/// <summary>
/// The session setting keeps governing providers that answer with the forbidden page; a failed-sign-in provider always ends the session.
/// </summary>
public class and_the_provider_answers_denials_like_a_failed_sign_in_without_session_termination : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        SignedInThroughProvider(C.OidcDenialResponse.FailedSignIn);
        DenyIdentity();
        _config.Session.TerminateOnIdentityDenial = false;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_still_terminate_the_session() => ShouldHaveTerminatedSession();
}
