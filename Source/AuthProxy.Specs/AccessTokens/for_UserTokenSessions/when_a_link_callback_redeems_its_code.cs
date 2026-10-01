// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_link_callback_redeems_its_code : given.a_sign_in_redeeming_its_code
{
    void Establish() => _properties.Items[Links.LinkMiddleware.LinkModePropertyKey] = "true";

    Task Because() => UserTokenSessions.Capture(_context);

    [Fact] void should_keep_nothing_for_an_identity_that_is_not_signed_in() => _store.DidNotReceive().Create(Arg.Any<UserTokenSession>(), Arg.Any<CancellationToken>());
}
