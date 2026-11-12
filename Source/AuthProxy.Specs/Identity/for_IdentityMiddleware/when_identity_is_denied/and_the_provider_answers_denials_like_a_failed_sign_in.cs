// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_identity_is_denied;

/// <summary>
/// A person who navigates and is denied is told what a failed sign-in tells them, never that their identity was recognized.
/// </summary>
public class and_the_provider_answers_denials_like_a_failed_sign_in : given.an_identity_middleware
{
    void Establish()
    {
        ResolveTenant();
        SignedInThroughProvider(C.OidcDenialResponse.FailedSignIn);
        DenyIdentity();
        Navigate();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_terminate_the_session() => ShouldHaveTerminatedSession();
    [Fact] void should_not_write_the_forbidden_page() => _errorPages.DidNotReceiveWithAnyArgs().WriteErrorPageAsync(default!, default!, default);
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_redirect() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);

    [Fact] void should_redirect_exactly_where_a_failed_sign_in_does() =>
        _context.Response.Headers.Location.ToString().ShouldEqual(
            RemoteAuthenticationFailureHandler.FailedSignInLocation(SignInFailureReason.RemoteFailure, RelativeRedirect.Resolve(ProtectedPath)));

    [Fact] void should_clear_the_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenant}=; expires");
}
