// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_an_ordinary_oauth_login_has_a_verified_email_endpoint_configured : an_oauth_verified_email_callback
{
    protected override bool HasInvitationState => false;

    async Task Because() => await InvokeCallback();

    [Fact] void should_not_call_the_invitation_only_endpoint() => _handler.VerifiedEmailRequests.ShouldEqual(0);
    [Fact] void should_preserve_the_ordinary_login_email() => _context.Principal!.Claims.Single(_ => _.Type == "email").Value.ShouldEqual("untrusted@example.com");
}
