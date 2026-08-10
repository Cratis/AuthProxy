// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_RemoteAuthenticationFailureHandler;

public class when_remote_sign_in_fails_with_an_absolute_return_url : given.a_remote_authentication_failure_context
{
    RemoteFailureContext _failureContext;

    void Establish() =>
        _failureContext = new RemoteFailureContext(_context, _scheme, _options, new InvalidOperationException("Correlation failed."))
        {
            Properties = new AuthenticationProperties { RedirectUri = "https://evil.test/phish" }
        };

    async Task Because() => await RemoteAuthenticationFailureHandler.HandleRemoteFailure(_failureContext);

    [Fact] void should_not_carry_the_absolute_target_forward() =>
        _context.Response.Headers.Location.ToString().ShouldEqual(
            $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.RemoteFailure}");
}
