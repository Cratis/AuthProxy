// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_an_oauth_verified_email_endpoint_returns_no_primary_address : an_oauth_verified_email_callback
{
    protected override string VerifiedEmailResponse => "[]";

    async Task Because() => await InvokeCallback();

    [Fact] void should_remove_the_unverified_user_information_email() => _context.Principal!.Claims.Any(_ => _.Type == "email").ShouldBeFalse();
    [Fact] void should_remove_caller_supplied_verification_authority() => _context.Principal!.Claims.Any(_ => _.Type == "email_verified").ShouldBeFalse();
}
