// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_sign_in_redeems_its_code : given.a_sign_in_redeeming_its_code
{
    Task Because() => UserTokenSessions.Capture(_context);

    [Fact] void should_not_store_tokens_before_validation_and_ticket_handlers_succeed() => _store.DidNotReceive().Create(Arg.Any<UserTokenSession>(), Arg.Any<CancellationToken>());
    [Fact] void should_not_create_a_cookie_token_session_yet() => _properties.Items.ContainsKey(UserTokenSessions.PropertiesKey).ShouldBeFalse();
    [Fact] void should_put_no_tokens_on_the_session() => _properties.GetTokens().ShouldBeEmpty();
}
