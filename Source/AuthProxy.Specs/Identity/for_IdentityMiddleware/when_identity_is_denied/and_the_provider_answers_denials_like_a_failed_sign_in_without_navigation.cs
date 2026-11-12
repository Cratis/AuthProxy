// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

/// <summary>
/// A scripted caller gets what an unauthenticated caller already gets, not a 403 that says the identity was recognized.
/// </summary>
public class and_the_provider_answers_denials_like_a_failed_sign_in_without_navigation : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        SignedInThroughProvider(C.OidcDenialResponse.FailedSignIn);
        DenyIdentity();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_answer_unauthorized() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_terminate_the_session() => ShouldHaveTerminatedSession();
    [Fact] void should_not_write_the_forbidden_page() => _errorPages.DidNotReceiveWithAnyArgs().WriteErrorPageAsync(default!, default!, default);
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
}
