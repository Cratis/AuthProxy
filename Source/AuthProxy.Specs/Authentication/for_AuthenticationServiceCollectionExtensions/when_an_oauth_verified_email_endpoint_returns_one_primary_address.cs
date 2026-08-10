// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_an_oauth_verified_email_endpoint_returns_one_primary_address : an_oauth_verified_email_callback
{
    async Task Because() => await InvokeCallback();

    [Fact] void should_replace_user_information_email_with_the_verified_address() => _context.Principal!.Claims.Single(_ => _.Type == "email").Value.ShouldEqual("verified@example.com");
    [Fact] void should_attest_verified_email_only_from_the_verification_endpoint() => _context.Principal!.Claims.Single(_ => _.Type == "email_verified").Value.ShouldEqual(bool.TrueString.ToLowerInvariant());
}
