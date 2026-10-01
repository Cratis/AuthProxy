// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_sign_in_redeems_its_code : given.a_sign_in_redeeming_its_code
{
    Task Because() => UserTokenSessions.Capture(_context);

    [Fact] void should_keep_the_refresh_token_server_side() => _store.Received(1).Create(new UserTokenSession("workforce", "refresh-token"), Arg.Any<CancellationToken>());
    [Fact] void should_put_only_the_session_identifier_on_the_session() => _properties.Items[UserTokenSessions.PropertiesKey].ShouldEqual("session-id");
    [Fact] void should_put_no_tokens_on_the_session() => _properties.GetTokens().ShouldBeEmpty();
}
