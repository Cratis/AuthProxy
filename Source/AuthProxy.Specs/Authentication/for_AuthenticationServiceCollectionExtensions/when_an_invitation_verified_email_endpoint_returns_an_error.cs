// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_an_invitation_verified_email_endpoint_returns_an_error : an_oauth_verified_email_callback
{
    Exception? _exception;

    protected override HttpStatusCode VerifiedEmailStatusCode => HttpStatusCode.ServiceUnavailable;

    async Task Because() => _exception = await Record.ExceptionAsync(InvokeCallback);

    [Fact] void should_not_break_provider_login() => _exception.ShouldBeNull();
    [Fact] void should_remove_email_authority() => _context.Principal!.Claims.Any(_ =>
        string.Equals(_.Type, "email", StringComparison.Ordinal)
        || string.Equals(_.Type, "email_verified", StringComparison.Ordinal)).ShouldBeFalse();
}
