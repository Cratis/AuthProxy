// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_RemoteAuthenticationFailureHandler;

public class when_the_identity_provider_denies_access : given.a_remote_authentication_failure_context
{
    AccessDeniedContext _accessDeniedContext;

    void Establish() =>
        _accessDeniedContext = new AccessDeniedContext(_context, _scheme, _options)
        {
            Properties = new AuthenticationProperties { RedirectUri = "/dashboard" }
        };

    async Task Because() => await RemoteAuthenticationFailureHandler.HandleAccessDenied(_accessDeniedContext);

    [Fact] void should_handle_the_response() => _accessDeniedContext.Result.Handled.ShouldBeTrue();

    [Fact] void should_redirect_to_provider_selection_with_the_access_denied_reason() =>
        _context.Response.Headers.Location.ToString().ShouldEqual(
            $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.AccessDenied}&returnUrl={Uri.EscapeDataString("/dashboard")}");
}
