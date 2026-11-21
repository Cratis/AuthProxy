// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

/// <summary>
/// An outage of the service that verifies identity is not a refusal: the caller is told the service is unavailable, and
/// their session survives even where a denial would end it.
/// </summary>
public class and_verification_is_unavailable : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        EnableSessionTermination();
        SignedInThroughProvider(C.OidcDenialResponse.Forbidden);
        MakeVerificationUnavailable();
        Navigate();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_answer_service_unavailable() => ShouldHaveBeenAnsweredAsUnavailable();
    [Fact] void should_not_say_access_was_denied() => _errorPages.DidNotReceive().WriteErrorPageAsync(_context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
    [Fact] void should_preserve_the_session() => ShouldHavePreservedSession();
    [Fact] void should_not_let_the_request_through() => _nextCalled.ShouldBeFalse();
}
