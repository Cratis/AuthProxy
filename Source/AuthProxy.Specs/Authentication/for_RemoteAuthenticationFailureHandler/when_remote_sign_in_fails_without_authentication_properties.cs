// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_RemoteAuthenticationFailureHandler;

public class when_remote_sign_in_fails_without_authentication_properties : given.a_remote_authentication_failure_context
{
    RemoteFailureContext _failureContext;

    void Establish() =>
        _failureContext = new RemoteFailureContext(_context, _scheme, _options, new InvalidOperationException("The oauth state was missing or invalid."));

    async Task Because() => await RemoteAuthenticationFailureHandler.HandleRemoteFailure(_failureContext);

    [Fact] void should_handle_the_response() => _failureContext.Result.Handled.ShouldBeTrue();

    [Fact] void should_redirect_to_provider_selection_with_only_the_reason() =>
        _context.Response.Headers.Location.ToString().ShouldEqual(
            $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.RemoteFailure}");
}
